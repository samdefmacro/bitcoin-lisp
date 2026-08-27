(in-package #:bitcoin-lisp)

#+sbcl
(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :sb-sprof))

;;; Bitcoin Node
;;;
;;; Main entry point for the Bitcoin full node.
;;; Coordinates all subsystems: networking, storage, validation.

;;;; Network Configuration

(defconstant +sync-ticks-per-second+ 5
  "How finely the sync thread's between-cycle wait is sliced.

The wait exists to pump peer messages while nothing else is due, and the SLEEP
runs before the pump — so the tick length is the floor on how fast an announced
block can be noticed, and a propagation spans two ticks. At one tick per second
diag/propagation_probe.py measured a flat 2s on regtest for a block that takes
0.01s to mine.

Five is a bound, not a tuning: everything in that loop which wants a per-second
cadence is gated on the derived SECOND rather than on the tick, so shortening
the tick cannot make the trickle, ping or dump work run more often. Core's
ProcessMessages runs continuously; this moves in that direction without giving
up the loop's shape.")

(defconstant +testnet3+ :testnet3)
(defconstant +testnet4+ :testnet4)
(defconstant +signet+ :signet)
(defconstant +mainnet+ :mainnet)

(defconstant +regtest+ :regtest)

(defvar *network* +testnet4+
  "Current network mode (:testnet3, :testnet4, :signet, :regtest, or :mainnet).")

(defun network-magic (network)
  "NETWORK's message-start bytes (chain-params-magic)."
  (bl.chain:chain-params-magic (bl.chain:find-chain-params network)))

(defun network-port (network)
  "NETWORK's default P2P port (chain-params-port)."
  (bl.chain:chain-params-port (bl.chain:find-chain-params network)))

(defun %normalize-datadir (datadir)
  "DATADIR as a string that names a DIRECTORY, whatever spelling it arrived in.

Core accepts -datadir with or without a trailing separator. Here \"/tmp/x\"
parses as a FILE pathname whose NAME is \"x\", so merging \"regtest/chainstate/\"
onto it yields /tmp/regtest/chainstate/x — the node opens its databases
somewhere nobody asked for, and the first symptom is a LevelDB NotFound on a
path the operator never typed. Kept a STRING because the config layer treats it
as one."
  (when datadir
    (namestring (uiop:ensure-directory-pathname datadir))))

;;;; -blocknotify / -startupnotify / -shutdownnotify (Core init.cpp:255-266,
;;;; 2009-2019)
;;;;
;;;; An operator hook: run a shell command when something happens. The runner
;;;; itself (RUN-NOTIFY-COMMAND) lives in logging.lisp, early enough that the
;;;; wallet can reach it for -walletnotify; what lives here is the set of hooks
;;;; the NODE fires.

(defvar *connect-nodes* '()
  "-connect targets (Core m_specified_outgoing): peer specs to dial and keep
dialed, and NOTHING else. Deliberately not the node's added-nodes list, because
getaddednodeinfo reports -addnode and not -connect, exactly as Core's does —
both are nonetheless dialed as MANUAL connections.")

(defvar *pending-test-connections* '()
  "Connections the addconnection RPC has asked for, as (address . conn-type),
drained by the sync thread. A queue rather than a direct dial because node-peers
is single-writer by design; Core's own AddConnection likewise returns before the
connection completes. Regtest-only, like the RPC.")

(defvar *seed-nodes* '()
  "-seednode targets (Core connOptions.vSeedNodes): peers dialed once, purely to
collect addresses, and disconnected as soon as they deliver some. Core queues
them as m_addr_fetches and opens ConnectionType::ADDR_FETCH connections; the
disconnect lives in the addr handler, next to Core's.")

(defvar *use-addrman-outgoing* t
  "Core's CConnman m_use_addrman_outgoing (net.h:1095). NIL once -connect was
given in any form. A global rather than a node slot for the same reason
*dns-seed-enabled* and *block-notify-command* are: it is start-up configuration
that never varies within a run.")

(defun addrman-outgoing-enabled-p ()
  "Whether this node may open outbound connections of its own choosing (Core
CConnman::GetUseAddrmanOutgoing, net.h:1168).

NIL once -connect was given in ANY form: with -connect=<addr> Core's
ThreadOpenConnections takes the specified-addresses branch and never reaches
the addrman code at all, and with -connect=0 the thread is not started
(net.cpp:3540) — so no feeler, no block-relay slot, no replacement dial. Only
the MANUAL connections (-connect and -addnode) remain."
  *use-addrman-outgoing*)

(defvar *block-notify-command* nil
  "Shell command to run when the best block changes; %s is replaced by the
block hash (Core -blocknotify, init.cpp:498).")

(defvar *shutdown-notify-commands* '()
  "Shell commands to run at shutdown, in order (Core -shutdownnotify). Core
JOINS these — shutdown waits for them — because a detached command racing
process exit is a command that may not run at all (init.cpp:257-265).")

(defun notify-block-tip (hash)
  "Run -blocknotify for a new best block, if configured."
  (when *block-notify-command*
    (run-notify-command *block-notify-command*
                        :value (bl.crypto:bytes-to-hex hash))))

(defvar *pid-file-path* nil
  "The PID file this process created, or NIL. Set by WRITE-PID-FILE and cleared
by REMOVE-PID-FILE; Core's g_generated_pid serves the same purpose — a pid file
we did NOT create is never removed.")

(defun pid-file-path (pid-arg data-directory)
  "Where -pid points: PID-ARG, prefixed by DATA-DIRECTORY when relative (Core
GetPidFile -> AbsPathForConfigVal, init.cpp:178-181). NIL when -pid was
negated, which Core treats as \"write no pid file\" (init.cpp:185)."
  (let ((arg (cond ((null pid-arg) "bitcoin-lisp.pid")
                   ((not (stringp pid-arg)) pid-arg)
                   ((or (string= pid-arg "0") (string= pid-arg "")) nil)
                   (t pid-arg))))
    (when arg
      (if (uiop:absolute-pathname-p arg)
          (pathname arg)
          (merge-pathnames arg (uiop:ensure-directory-pathname
                                (or data-directory "./")))))))

(defun write-pid-file (pid-arg data-directory)
  "Write our PID where -pid says (Core CreatePidFile, init.cpp:183-199).

Core makes a write failure a fatal InitError, and so do we: an operator who
asked for a pid file and silently did not get one has a supervisor that will
never find this process."
  (let ((path (pid-file-path pid-arg data-directory)))
    (when path
      (handler-case
          (with-open-file (out path :direction :output
                                    :if-exists :supersede
                                    :if-does-not-exist :create)
            (format out "~D~%" (sb-posix:getpid)))
        (error (e)
          (error "Unable to create the PID file '~A': ~A" path e)))
      (setf *pid-file-path* path)
      path)))

(defun remove-pid-file ()
  "Remove the pid file we created (Core RemovePidFile, init.cpp:200-208). A
failure is a warning, never a reason to fail shutdown."
  (let ((path *pid-file-path*))
    (when path
      (setf *pid-file-path* nil)
      (handler-case (delete-file path)
        (error (e)
          (log-warn "Unable to remove PID file (~A): ~A" path e))))))

(defun run-shutdown-notify ()
  "Run every -shutdownnotify command and WAIT for it (Core joins them,
init.cpp:263-265): a detached command racing process exit may not run at all."
  (dolist (command *shutdown-notify-commands*)
    (run-notify-command command :wait t)))

(defun apply-rpc-config-globals (alist)
  "Apply the process-global RPC options from a merged config ALIST.

Separate from APPLY-CONFIG-GLOBALS purely because of load order: config.lisp
compiles BEFORE src/rpc/package.lisp, so a package-qualified reference to
BITCOIN-LISP.RPC there is a READ error, not a link error. Called from
START-NODE-FROM-ARGS immediately after its sibling."
  (flet ((lk (k) (let ((c (assoc k alist :test #'string=))) (and c (cdr c)))))
    ;; -rpccookiefile: where the auth cookie goes (Core init.cpp:710). A
    ;; relative path hangs off the data directory.
    (let ((v (lk "rpccookiefile")))
      (when v (setf bl.rpc:*rpc-cookie-file* v)))
    ;; -rpccookieperms=owner|group|all (Core init.cpp:711). Loosening who may
    ;; read the cookie is loosening who may drive the RPC, so an unrecognised
    ;; audience is an error rather than a silent fall back to the default.
    (let ((v (lk "rpccookieperms")))
      (when v
        (let ((perms (bl.rpc:parse-rpc-cookie-perms v)))
          (unless perms
            (error "Invalid -rpccookieperms=~A (must be owner, group or all)" v))
          (setf bl.rpc:*rpc-cookie-perms* perms))))
    ;; -rpcthreads: cap on concurrent RPC handler threads (Core
    ;; DEFAULT_HTTP_THREADS = 16).
    (let ((v (lk "rpcthreads")))
      (when v
        (let ((n (conf-parse-int v)))
          (unless (and n (plusp n))
            (error "Invalid value for -rpcthreads=~A (must be a positive integer)" v))
          (setf bl.rpc:*rpc-threads* n))))
    ;; -rpcservertimeout: seconds an idle RPC connection is held (Core
    ;; DEFAULT_HTTP_SERVER_TIMEOUT). 0 means no timeout, as in Core.
    (let ((v (lk "rpcservertimeout")))
      (when v
        (let ((n (conf-parse-int v)))
          (unless (and n (>= n 0))
            (error "Invalid value for -rpcservertimeout=~A (must be a non-negative integer)" v))
          (setf bl.rpc:*rpc-server-timeout* (if (zerop n) nil n)))))
    ;; --- Wallet knobs over paths that already exist (track D's Wallet group).
    ;; Every one of these has a special with Core's name and default already;
    ;; what was missing was the option that sets it.
    ;;
    ;; They live here rather than in APPLY-CONFIG-GLOBALS for the same load-order
    ;; reason the RPC ones do: these specials are in BITCOIN-LISP.RPC, whose
    ;; package config.lisp compiles before.
    (macrolet ((fee-knob (option place)
                 ;; Core's fee options are BTC/kvB on the command line and
                 ;; satoshis internally, as -maxtxfee and -fallbackfee already
                 ;; are in apply-config-globals.
                 `(let ((v (lk ,option)))
                    (when v
                      (let ((sats (conf-parse-money v)))
                        (unless sats
                          (error "Invalid amount for -~A=~A" ,option v))
                        (setf ,place sats)))))
               (int-knob (option place &key (min 0))
                 `(let ((v (lk ,option)))
                    (when v
                      (let ((n (conf-parse-int v)))
                        (unless (and n (>= n ,min))
                          (error "Invalid value for -~A=~A" ,option v))
                        (setf ,place n)))))
               (bool-knob (option place)
                 `(let ((v (lk ,option)))
                    (when v (setf ,place (conf-parse-bool v))))))
      (fee-knob "mintxfee" bl.rpc::*wallet-min-tx-fee*)
      (fee-knob "discardfee" bl.rpc::*wallet-discard-rate*)
      (fee-knob "consolidatefeerate" bl.rpc::*wallet-consolidate-feerate*)
      (fee-knob "maxapsfee" bl.rpc::*wallet-max-aps-fee*)
      (int-knob "txconfirmtarget" bl.rpc::*wallet-confirm-target* :min 1)
      (bool-knob "walletrbf" bl.rpc::*wallet-signal-rbf*)
      (bool-knob "spendzeroconfchange" bl.rpc::*wallet-spend-zero-conf-change*)
      (bool-knob "walletrejectlongchains" bl.rpc::*wallet-reject-long-chains*)
      ;; -keypool sizes the keypool of wallets created AFTER it is set; an
      ;; existing wallet keeps the size it was made with, as in Core, where the
      ;; keypool size is per-wallet state.
      (int-knob "keypool" bl.rpc::+default-keypool-size+ :min 1))
    ;; -walletdir relocates <datadir>/wallets/ (Core init.cpp). Relative paths
    ;; hang off the data directory, as -rpccookiefile does.
    (let ((v (lk "walletdir")))
      (when v (setf bl.rpc::*wallet-directory* v)))
    ;; -walletnotify: an operator hook, fired from AddToWallet.
    (let ((v (lk "walletnotify")))
      (when v (setf bl.rpc::*wallet-notify-command* v)))
    alist))

(defun %start-rpc-early (node rpc-port rpc-bind rpc-bind-supplied-p
                         rpc-user rpc-password rpc-auth rpc-allow-ip
                         rest-enabled network webui webui-supplied-p
                         webui-path webui-open)
  "Bring the RPC server up before the slow parts of startup.

Split out of START-NODE only because it is called from the middle of it now
rather than the end; the body is unchanged. The server is reachable from this
point and answers -28 for every method until FINISH-RPC-WARMUP."
  ;; Web UI default (gui-plan §2): on everywhere except mainnet, where
  ;; enabling it is the operator's explicit choice (-webui).
  (let* ((webui-enabled (if webui-supplied-p
                            (and webui t)
                            (not (eq network :mainnet))))
         (server (bl.rpc:start-rpc-server node
                                                    :port rpc-port
                                                    :bind rpc-bind
                                                    :bind-supplied-p
                                                    rpc-bind-supplied-p
                                                    :user rpc-user
                                                    :password rpc-password
                                                    :rpc-auth rpc-auth
                                                    :allow-ip rpc-allow-ip
                                                    :rest-enabled rest-enabled
                                                    :ui-enabled webui-enabled
                                                    :ui-directory webui-path
                                                    :warmup "Loading...")))
    ;; -webuiopen: pop the local browser at the dashboard. Logged, never
    ;; fatal (open-browser-to-ui catches everything).
    (when (and server webui-enabled webui-open)
      (bl.rpc:open-browser-to-ui rpc-port))
    server))

(defun %ensure-wallets-subdirectory (data-directory network)
  "Create wallets/ under a datadir that did not exist yet (Core
common/init.cpp:45-63).

Both the base path and the network path, and only when the path itself is
being created — an existing datadir keeps whatever layout it has, which is the
backwards-compatibility rule Core states in that comment."
  (flet ((claim (dir)
           (let ((path (uiop:ensure-directory-pathname dir)))
             (unless (probe-file path)
               (ensure-directories-exist (merge-pathnames "wallets/" path))))))
    (let ((base (uiop:ensure-directory-pathname data-directory)))
      (claim base)
      (claim (network-data-path base network)))))

(defun %resolve-log-file (log-file data-directory &optional network)
  "The path to log to, or NIL for no file log.

LOG-FILE is -logfile: a path uses it as given, and an explicit \"0\" or \"\"
turns file logging off the way Core's -debuglogfile=0 does. Anything else —
including the usual case of no -logfile at all — is debug.log in NETWORK's
directory under DATA-DIRECTORY.

The NETWORK directory, not the base one. Core resolves -debuglogfile against
GetDataDirNet() (init.cpp, AbsPathForConfigVal), so regtest logs to
<datadir>/regtest/debug.log and only mainnet logs to <datadir>/debug.log. Core's
functional framework reads exactly that path — test_node.py's debug_log_path is
`datadir / chain / \"debug.log\"` — and every assert_debug_log in the suite
goes through it. Writing to the base directory instead does not fail: the
framework opens a file that is not there, finds nothing in it, and reports the
expected message as missing. That is a whole class of tests reporting a
node-behaviour failure for a path bug.

Passing no NETWORK keeps the base directory, which is what the pre-Core callers
and the unit tests expect."
  (flet ((net-dir ()
           (and data-directory
                (let ((dir (uiop:ensure-directory-pathname data-directory)))
                  (if network (network-data-path dir network) dir)))))
    (cond ((and (stringp log-file)
                (or (string= log-file "0") (string= log-file "")))
           nil)
          ;; A RELATIVE -debuglogfile is resolved against the network
          ;; directory, not the process working directory (Core
          ;; AbsPathForConfigVal, net_specific=true). feature_logging.py starts
          ;; a node with -debuglogfile=foo.log and then looks for
          ;; <datadir>/<chain>/foo.log; taken as given it lands wherever the
          ;; node happened to be started from, which for a service is /.
          ((and (stringp log-file) (plusp (length log-file)))
           (let ((path (pathname log-file))
                 (dir (net-dir)))
             (if (and dir (not (eq :absolute (first (pathname-directory path)))))
                 (namestring (merge-pathnames path dir))
                 log-file)))
          (log-file log-file)
          (data-directory
           (let ((dir (net-dir)))
             (namestring (merge-pathnames "debug.log" dir))))
          (t nil))))

(defun listen-port (network)
  "The P2P LISTEN port: -port when given, else NETWORK's default (Core
GetListenPort, net.cpp:138-162). Dialing peers keeps the chain default —
Core's -port only moves the listening/advertised side."
  (or *p2p-port-override* (network-port network)))

(defun network-dns-seeds (network)
  "NETWORK's DNS seeds (chain-params-dns-seeds)."
  (bl.chain:chain-params-dns-seeds (bl.chain:find-chain-params network)))

(defun network-rpc-port (network)
  "NETWORK's default RPC port (chain-params-rpc-port)."
  (bl.chain:chain-params-rpc-port (bl.chain:find-chain-params network)))

(defvar *mainnet-relay-enabled* nil
  "Whether transaction relay is enabled on mainnet. Default NIL for safety.")

(defvar *max-inbound-connections* 114
  "Inbound connections we keep (excess are disconnected at merge time). Set by
start-node via automatic-inbound-capacity; the default is Core's 125 - 11.")

;;;; Node State

(defstruct node
  "Bitcoin node state."
  (network :testnet3 :type keyword)
  (data-directory nil :type (or null pathname))
  ;; Chainstates, ordered like Core ChainstateManager::m_chainstates
  ;; (validation.h:1377): exactly one today (the primary, fully-validated
  ;; chainstate, owning the coins view); an assumeutxo snapshot activation
  ;; appends a second. Read via node-current-chainstate /
  ;; node-historical-chainstate / node-validated-chainstate, or the
  ;; node-chain-state / node-utxo-set compatibility accessors below.
  (chainstates '() :type list)
  (block-store nil)
  (mempool nil)
  (tx-index nil)  ; Transaction index (optional, for getrawtransaction)
  (blockfilterindex nil)  ; BIP158 basic block filter index (optional)
  (coinstatsindex nil)  ; per-height UTXO stats + MuHash index (optional)
  (txospenderindex nil)  ; outpoint -> spending tx index (optional, -txospenderindex)
  ;; Wallet manager (bl.rpc:wallet-manager) fanning RPCs out to
  ;; loaded wallets by name; NIL when wallet support is disabled (mainnet
  ;; default). Wallet P1, docs/wallet-plan.md §4.
  (wallet-manager nil)
  (fee-estimator nil)  ; Fee rate estimator for estimatesmartfee
  (address-book nil)  ; Persistent peer address database
  (recent-rejects nil)  ; Recently rejected transaction filter (DoS protection)
  (peers '() :type list)
  (running nil :type boolean)
  (log-level :info :type keyword)
  (sync-thread nil :type (or null bt:thread))
  (syncing nil :type boolean)
  ;; Inbound listening: server socket + accept thread, and a lock-guarded
  ;; hand-off list. The listener thread pushes handshaked inbound peers onto
  ;; pending-inbound-peers (under LOCK); the sync thread merges them into PEERS,
  ;; keeping PEERS single-writer so the drain loop never races a push.
  (listener-socket nil)
  (listener-thread nil :type (or null bt:thread))
  ;; Onion-service listener: a second accept loop on 127.0.0.1:(port+1) that
  ;; the local Tor daemon forwards inbound onion connections to (Core's
  ;; onion_binds + default onion service target). Peers accepted here are
  ;; tagged inbound-onion (their true network is :torv3).
  (onion-listener-socket nil)
  (onion-listener-thread nil :type (or null bt:thread))
  ;; The torcontrol client (bl.net:tor-controller) keeping
  ;; the v3 onion service registered with the local Tor daemon, or NIL.
  (tor-controller nil)
  (pending-inbound-peers '() :type list)
  (lock (bt:make-recursive-lock "node-lock"))
  (known-addresses '() :type list)
  ;; setnetworkactive: when NIL, the node makes no new outbound connections and
  ;; accepts no inbound ones (existing peers are dropped on toggle-off).
  (network-active t :type boolean)
  ;; addnode "add": manually-pinned peer specs ("host" or "host:port") that the
  ;; maintenance loop keeps connected, independent of max-peers.
  (added-nodes '() :type list)
  ;; addnode "onetry": one-shot dial requests handed off to the sync thread so
  ;; node-peers stays single-writer (only the sync thread pushes to it).
  (pending-onetry '() :type list)
  ;; Durable at-tip liveness signal (item #6). last-tip-advance-time is the
  ;; node clock (get-node-time, so setmocktime reaches it) of the last observed active-chain tip
  ;; advance; last-tip-height is the tip height at that observation. Unlike the
  ;; ibd-context copy (nil between sync passes), these persist so the
  ;; /rest/health probe can tell a live, progressing node from a wedged one
  ;; (sync thread alive but tip frozen). Seeded at sync start;
  ;; note-node-tip-progress bumps them from the sync loop.
  (last-tip-advance-time 0 :type integer)
  (last-tip-height 0 :type integer)
  (max-peers 8 :type (unsigned-byte 8)))

;;; Chainstate selection (Core ChainstateManager, validation.h:1119-1145).
;;; With one chainstate all three return it.

(defun node-current-chainstate (node)
  "The chainstate targeting the network tip (Core CurrentChainstate). New
blocks extend it, the mempool validates against its coins view, and RPC
reports it as the active chainstate."
  (bl.store:select-current-chainstate (node-chainstates node)))

(defun node-historical-chainstate (node)
  "The chainstate re-deriving history toward a snapshot base block (Core
HistoricalChainstate); NIL when no background validation is in progress."
  (bl.store:select-historical-chainstate (node-chainstates node)))

(defun node-validated-chainstate (node)
  "The fully-validated chainstate (Core ValidatedChainstate) — the one
indexes bind to, since they index blocks in order from genesis."
  (bl.store:select-validated-chainstate (node-chainstates node)))

;;; Compatibility accessors for the former chain-state / utxo-set node slots.
;;; The chain-state struct now owns its coins view, and the node holds a
;;; chainstates list; these read/write the current chainstate so existing
;;; call sites (and tests) keep their single-chainstate shape.

(defun node-chain-state (node)
  "The current (active) chainstate — the former chain-state slot."
  (node-current-chainstate node))

(defun (setf node-chain-state) (chainstate node)
  "Install CHAINSTATE as the node's current chainstate, replacing an existing
one. A replaced chainstate's coins view carries over when CHAINSTATE has
none, preserving the former independent-slot semantics (setting chain-state
never clobbered utxo-set)."
  (let ((old (node-current-chainstate node)))
    (when (and old (null (bl.store:chain-state-coins-view chainstate)))
      (setf (bl.store:chain-state-coins-view chainstate)
            (bl.store:chain-state-coins-view old)))
    (setf (node-chainstates node)
          (if old
              (substitute chainstate old (node-chainstates node))
              (append (node-chainstates node) (list chainstate)))))
  chainstate)

(defun node-utxo-set (node)
  "The current chainstate's coins view — the former utxo-set slot."
  (let ((cs (node-current-chainstate node)))
    (and cs (bl.store:chain-state-coins-view cs))))

(defun (setf node-utxo-set) (view node)
  "Set the current chainstate's coins view — the former utxo-set slot."
  (let ((cs (node-current-chainstate node)))
    (unless cs
      (error "Cannot set the node's utxo-set: no current chainstate exists"))
    (setf (bl.store:chain-state-coins-view cs) view)))

(defvar *node* nil
  "Current running node instance.")

(defvar *node-start-time* nil
  "Unix time the node was started (set by start-node); basis for the uptime RPC.")

;;;; At-tip liveness signal (item #6): a durable, node-level record of when the
;;;; active chain tip last advanced, plus the /rest/health decision it feeds.
;;;; The ibd-context copy (networking) is nil between sync passes; these node
;;;; slots persist so an external monitor can distinguish a live, progressing
;;;; node from a wedged one (sync thread alive but tip frozen — the failure
;;;; mode the layer-5 work chased).

(defparameter *health-max-tip-staleness-seconds* 5400
  "Seconds the active chain tip may go without advancing before /rest/health
reports the node unhealthy (HTTP 503). Deliberately generous (90 min): the goal
is to surface a wedged-but-running node, not normal quiet periods. Testnet4
permits 20-minute minimum-difficulty blocks and occasional longer gaps, so a
tight threshold would flap; a multi-hour wedge is still caught quickly.")

(defun note-node-tip-progress (node)
  "Observe the active chain tip from the sync loop; if it rose past the last
height recorded on NODE, stamp NODE's durable last-tip-advance time. An O(1)
height read, safe to call every loop iteration. This is the persistent
counterpart to note-tip-advanced's ephemeral ibd-context slot."
  (let* ((cs (node-current-chainstate node))
         (h (and cs (bl.store:current-height cs))))
    (when (and (integerp h) (> h (node-last-tip-height node)))
      (setf (node-last-tip-height node) h
            (node-last-tip-advance-time node) (bl.ser:get-node-time)))))

(defun health-ok-p (sync-thread-alive-p seconds-since-tip
                    &optional (threshold *health-max-tip-staleness-seconds*))
  "Pure /rest/health decision: T (serve HTTP 200) iff the sync thread is alive
AND the tip advanced within THRESHOLD seconds; NIL (serve HTTP 503) otherwise.
Kept free of node state so it is directly unit-testable."
  (and sync-thread-alive-p
       (integerp seconds-since-tip)
       (<= seconds-since-tip threshold)
       t))

(defun node-tip-liveness (node)
  "Liveness report for the /rest/health endpoint, as
(values healthy-p seconds-since-tip synced-p). Lock-free and side-effect-free
(a health probe must neither block on the node lock nor mutate IBD state):
  HEALTHY-P         - health-ok-p of the two signals below.
  SECONDS-SINCE-TIP - wall-clock seconds since the last observed tip advance,
                      or MOST-POSITIVE-FIXNUM if the tip has never advanced.
  SYNCED-P          - node has left initial block download (latched IBD cache,
                      read without triggering initial-block-download-p's latch)."
  (let* ((alive (and (node-sync-thread node)
                     (bt:thread-alive-p (node-sync-thread node))
                     t))
         (last (node-last-tip-advance-time node))
         (seconds (if (plusp last)
                      (max 0 (- (bl.ser:get-node-time) last))
                      most-positive-fixnum))
         (synced (not bl.net::*cached-is-ibd*)))
    (values (health-ok-p alive seconds) seconds synced)))

;;;; Logging (macros and core functions defined in logging.lisp)

(defun show-logs (&key (n 20) (level :debug))
  "Show the last N log entries at or above LEVEL.
LEVEL can be :debug, :info, :warn, or :error."
  (let ((entries '())
        (min-level (log-level-value level)))
    (bt:with-lock-held (*log-lock*)
      (let ((start (if (< *log-buffer-count* +log-buffer-size+)
                       0
                       *log-buffer-index*)))
        (dotimes (i *log-buffer-count*)
          (let* ((idx (mod (+ start i) +log-buffer-size+))
                 (entry (aref *log-buffer* idx)))
            (when entry
              (push entry entries))))))
    ;; entries is now oldest-first after reverse
    (setf entries (nreverse entries))
    ;; Filter by level and take last n
    (let ((filtered (remove-if-not
                     (lambda (entry)
                       (let ((level-str (and (> (length entry) 22)
                                             (subseq entry 22 (position #\: entry :start 22)))))
                         (when level-str
                           (let ((entry-level (find-symbol (string-upcase (string-trim " " level-str)) :keyword)))
                             (and entry-level
                                  (>= (log-level-value entry-level) min-level))))))
                     entries)))
      (let ((to-show (last filtered n)))
        (format t "~%=== Last ~D Log Entries ===~%" (length to-show))
        (dolist (entry to-show)
          (format t "~A~%" entry))
        (format t "~%")
        (length to-show)))))

(defun clear-logs ()
  "Clear the log buffer."
  (bt:with-lock-held (*log-lock*)
    (dotimes (i +log-buffer-size+)
      (setf (aref *log-buffer* i) nil))
    (setf *log-buffer-index* 0)
    (setf *log-buffer-count* 0))
  t)

(defun enable-console-logging ()
  "Enable logging to the console (REPL)."
  (setf *log-stream* *standard-output*)
  t)

(defun disable-console-logging ()
  "Disable logging to the console. Logs still go to buffer and file."
  (setf *log-stream* nil)
  t)

(defvar *log-file-path* nil
  "Path the file log is currently open on, so SIGHUP can reopen it.")

(defconstant +recent-log-history-bytes+ 10000000
  "Core ShrinkDebugFile's RECENT_DEBUG_HISTORY_SIZE (logging.cpp): the tail
kept when the log file is scrolled at startup.")

(defun shrink-log-file (path)
  "Core's ShrinkDebugFile (logging.cpp): when the log at PATH has grown more
than 10% past RECENT_DEBUG_HISTORY_SIZE, restart the file holding only its last
RECENT_DEBUG_HISTORY_SIZE bytes. Returns T if it scrolled the file.

Runs BEFORE the file is opened for append, so nothing is writing to it while it
is rewritten. Note what this does and does not solve: it bounds the log across
restarts, not within one run — a node that stays up for weeks still grows an
unbounded file. Core's answer to that is the SIGHUP reopen below plus an
external logrotate, and ours is the same."
  (handler-case
      (let ((size (with-open-file (s path :direction :input
                                          :element-type (quote (unsigned-byte 8))
                                          :if-does-not-exist nil)
                    (and s (file-length s)))))
        (when (and size (> size (* 11 (floor +recent-log-history-bytes+ 10))))
          (let ((tail (make-array +recent-log-history-bytes+
                                  :element-type (quote (unsigned-byte 8)))))
            (with-open-file (s path :direction :input
                                    :element-type (quote (unsigned-byte 8)))
              (file-position s (- size +recent-log-history-bytes+))
              (let ((n (read-sequence tail s)))
                (with-open-file (out path :direction :output
                                          :element-type (quote (unsigned-byte 8))
                                          :if-exists :supersede
                                          :if-does-not-exist :create)
                  (write-sequence tail out :end n))))
            t)))
    ;; A log we cannot scroll is not a reason to refuse to start.
    (error (e)
      (format *error-output* "WARNING: could not shrink log file ~A: ~A~%" path e)
      nil)))

(defun start-file-logging (path)
  "Start logging to a file at PATH, scrolling it first if it has grown past
Core's threshold."
  (when *log-file-stream*
    (close *log-file-stream*))
  (shrink-log-file path)
  (setf *log-file-path* path)
  (setf *log-file-stream* (open path :direction :output
                                     :if-exists :append
                                     :if-does-not-exist :create))
  (format t "Logging to file: ~A~%" path)
  path)

(defun reopen-log-file ()
  "Close and reopen the log file at its current path (Core's SIGHUP handler,
which exists so an external logrotate can move the file and have the node
start writing to a fresh one). Without this, the node keeps writing to the
renamed inode and the rotated file grows forever while the new one stays
empty."
  (when *log-file-path*
    (when *log-file-stream*
      (ignore-errors (close *log-file-stream*)))
    (setf *log-file-stream*
          (open *log-file-path* :direction :output
                                :if-exists :append
                                :if-does-not-exist :create))
    t))

(defun install-sighup-log-reopen ()
  "Wire SIGHUP to REOPEN-LOG-FILE, the way Core does for logrotate."
  #+sbcl
  (ignore-errors
   (sb-sys:enable-interrupt
    sb-unix:sighup
    (lambda (&rest ignored)
      (declare (ignore ignored))
      (ignore-errors (reopen-log-file))))
   t))

(defun stop-file-logging ()
  "Stop logging to file."
  (when *log-file-stream*
    (close *log-file-stream*)
    (setf *log-file-stream* nil))
  (setf *log-file-path* nil)
  t)

;;;; Genesis block headers
;;; Genesis parameters from Bitcoin Core chainparams.cpp

(defun make-genesis-header (network)
  "Construct the genesis block header for NETWORK, taken from the full
genesis-block construction (bl.store:make-genesis-block) so the
merkle root is COMPUTED from the real per-network coinbase and the header
hash is verified against the known genesis hash. A previous version shared
mainnet's merkle-root constant across all networks, which was wrong for
testnet4 (its genesis coinbase differs; Core kernel/chainparams.cpp:367-379)."
  (bl.ser:bitcoin-block-header
   (bl.store:make-genesis-block network)))

;;;; Process entropy

(defconstant +random-seed-bytes+ 32
  "Bytes of OS entropy folded into the process CL:*RANDOM-STATE* seed.
Matches the 256-bit seed Core's FastRandomContext takes from GetRandHash().")

(defvar *random-state-seed* nil
  "The integer seed most recently installed into CL:*RANDOM-STATE* by
SEED-GLOBAL-RANDOM-STATE, NIL while the process is still running on SBCL's
build-time state. Recorded so startup (and a test) can tell 'seeded' from
'never seeded' — the two are indistinguishable by looking at draws.")

(defun %os-entropy-seed ()
  "+RANDOM-SEED-BYTES+ bytes from the OS CSPRNG as a positive integer.
IRONCLAD:*PRNG* is the OS PRNG (getrandom(2) / /dev/urandom), so two processes
started a microsecond apart get unrelated seeds. Falls back to a clock-derived
mix only if the OS source is unreachable: much weaker, but still not the
build-time constant, which is the property that matters here."
  (handler-case
      (ironclad:octets-to-integer (ironclad:random-data +random-seed-bytes+))
    (error (e)
      (log-warn "OS entropy source unavailable (~A); seeding the RNG from the clock" e)
      ;; SBCL's (make-random-state t) mixes sub-second time, so two starts in
      ;; the same second still diverge; the wall clock widens the seed.
      (logxor (random (expt 2 62) (make-random-state t))
              (ash (get-universal-time) 32)))))

(defun seed-global-random-state ()
  "Replace the process-global CL:*RANDOM-STATE* with one seeded from OS
entropy; return the seed.

SBCL's *random-state* is part of the saved core: it is IDENTICAL in every fresh
image (verified on 2.6.5 — `(random 1000000)` is 113500 on the first draw of
every run), because SBCL seeds it at build time rather than from the OS. A node
that never re-seeds therefore replays one fixed sequence on every start, and
every draw whose entire value is unpredictability becomes a stable fingerprint:
addr-relay Poisson timers and the initial-broadcast jitter
(networking/protocol.lisp), addrman's new/tried selection and its GetAddr
shuffle (networking/addrman.lisp), the sendtxrcncl salt and ping nonces
(networking/peer.lisp), the VERSION nonce (serialization/messages.lisp). Core
draws all of these from OS-seeded contexts — FastRandomContext (net.cpp:3728,
random.h:394) and PeerManagerImpl::m_rng (net_processing.cpp:2009), which is
deterministic only under the test-only `deterministic_rng` option.

Assigns the GLOBAL value deliberately: SBCL threads read the global binding of
*random-state* (they do not inherit the starter thread's dynamic bindings), and
the peers that draw the jitter above run on their own threads. Tests that need
a reproducible stream bind *random-state* around their own code — the
assignment then lands on that binding and leaves the global alone."
  (let ((seed (%os-entropy-seed)))
    (setf *random-state* (sb-ext:seed-random-state seed)
          *random-state-seed* seed)
    ;; Never log the seed itself: it predicts every subsequent draw. (The
    ;; message stays source-neutral — the fallback above logs its own warning.)
    (log-debug "Seeded *random-state* with a ~D-byte seed" +random-seed-bytes+)
    seed))

;;;; Startup Sequence

(defun init-node (data-directory &key (network :testnet3) (log-level :info))
  "Initialize a new node with the given data directory and network.
For mainnet, data is stored in a 'mainnet' subdirectory.
For testnet, data stays at the base directory (backward compatible)."
  ;; Validate network parameter
  (unless (member network '(:testnet3 :testnet4 :signet :regtest :mainnet))
    (error "Invalid network: ~A. Must be :testnet3, :testnet4, :signet, :regtest, or :mainnet." network))

  ;; Re-seed the process RNG here, at the head of the only startup path
  ;; (start-node calls init-node before it builds the address book, opens the
  ;; listener or dials a peer), so nothing draws from SBCL's build-time
  ;; sequence. See SEED-GLOBAL-RANDOM-STATE for what depends on this.
  (seed-global-random-state)

  ;; Set global network variable
  (setf *network* network)

  ;; Each chain's own powLimit (Core params.powLimit) from the table;
  ;; derive-target / check-proof-of-work reject targets above it. Signet's is
  ;; EASIER than mainnet's minimum (00000377ae...), so running it against the
  ;; mainnet limit rejected every real signet nBits, genesis included.
  (setf bl.store:*pow-limit-target*
        (bl.store:bits-to-target
         (bl.chain:chain-params-pow-limit-bits (bl.chain:find-chain-params network))))

  ;; Calculate data path — each network uses its own subdirectory, and WHICH
  ;; subdirectory is Core's (chainparamsbase.cpp:40-55). See NETWORK-DATA-PATH.
  ;; ENSURE-DIRECTORY-PATHNAME, not PATHNAME: "/tmp/x" parses as a FILE
  ;; pathname whose NAME is "x", so merging "regtest/chainstate/" onto it
  ;; yields /tmp/regtest/chainstate/x — the datadir silently moves and the
  ;; node opens its databases somewhere nobody asked for. Core accepts
  ;; -datadir with or without a trailing separator, and every caller that
  ;; passes one without a slash hit this.
  (let* ((base-path (uiop:ensure-directory-pathname data-directory))
         (data-path (network-data-path base-path network)))
    ;; Ensure data directory exists
    (ensure-directories-exist (merge-pathnames "dummy" data-path))

    ;; Set network configuration
    (setf bl.ser:*network-magic* (network-magic network))
    (setf bl.net:*current-port* (network-port network))
    (setf bl.net:*dns-seeds* (network-dns-seeds network))

    ;; Create node instance
    (make-node :network network
               :data-directory data-path
               :log-level log-level)))

;;;; Inbound listening

(defun count-inbound-peers (node)
  (count-if #'bl.net:peer-inbound (node-peers node)))

(defun merge-inbound-peers (node)
  "Move handshaked inbound peers from the lock-guarded hand-off list into the
node's peer list (capped at *max-inbound-connections*; excess are disconnected). Called
by the sync thread, so PEERS stays single-writer."
  (let ((pending (bt:with-recursive-lock-held ((node-lock node))
                   (prog1 (node-pending-inbound-peers node)
                     (setf (node-pending-inbound-peers node) nil)))))
    ;; node-peers is written only by the sync thread, but RPC threads read it
    ;; under node-lock; hold the lock around the count + push so those reads see
    ;; a consistent set. Recursive: evict-discouraged-inbound re-takes it.
    (dolist (peer pending)
      (bt:with-recursive-lock-held ((node-lock node))
        (cond
          ((< (count-inbound-peers node) *max-inbound-connections*)
           (push peer (node-peers node)))
          ;; At capacity: a discouraged existing inbound peer is preferred for
          ;; eviction (Bitcoin Core), so make room for the newcomer if we can.
          ((evict-discouraged-inbound node)
           (push peer (node-peers node)))
          ;; Otherwise evict the least valuable inbound peer (protecting the
          ;; most valuable) so slots churn toward better peers instead of the
          ;; newcomer always losing — Core's AttemptToEvictConnection.
          ((evict-least-valuable-inbound node)
           (push peer (node-peers node)))
          (t
           (log-info "Inbound peer cap reached; dropping ~A"
                     (bl.net:peer-address peer))
           (bl.net:disconnect-peer peer)))))))

(defun evict-discouraged-inbound (node)
  "If any existing inbound peer is discouraged, disconnect it and return T so a
new inbound connection can take its slot. NIL if none are discouraged."
  (bt:with-recursive-lock-held ((node-lock node))
    (let ((victim (find-if (lambda (p)
                             (and (bl.net:peer-inbound p)
                                  (bl.net:peer-discouraged-p
                                   (bl.net:peer-address p))))
                           (node-peers node))))
      (when victim
        (log-info "Evicting discouraged inbound peer ~A to admit a new connection"
                  (bl.net:peer-address victim))
        (setf (node-peers node) (remove victim (node-peers node)))
        (bl.net:disconnect-peer victim)
        t))))

(defconstant +evict-protect-netgroup+ 4
  "Core SelectNodeToEvict: 4 peers protected by keyed netgroup
(eviction.cpp:186-188). Deterministic but unpredictable — an attacker cannot
tell which netgroups will be protected without the node's key.")
(defconstant +evict-protect-min-ping+ 8
  "8 peers with the lowest MINIMUM ping (:189-191). Was 4 here.")
(defconstant +evict-protect-tx+ 4
  "4 peers that most recently gave us a novel mempool transaction (:192-194).")
(defconstant +evict-protect-block-relay-only+ 8
  "8 NON-tx-relay peers that gave us novel blocks (:195-197). Missing here
entirely, which meant a block-relay-only peer doing exactly the job it exists
for was no safer than an idle one.")
(defconstant +evict-protect-block+ 4
  "4 peers that most recently gave us a novel block (:199-201).")

(defun %evict-erase-last-k (candidates comparator k &optional filter)
  "Core EraseLastKElements: sort CANDIDATES by COMPARATOR and REMOVE the last K
that satisfy FILTER — \"remove\" meaning protect, since this list is the
eviction pool. Returns the remaining candidates.

The comparator orders WORST-first, so the last K are the best K by that
measure. FILTER restricts the pass to a subset (Core's block-relay-only pass is
the only one that uses it) without letting the excluded peers consume slots."
  (let* ((eligible (if filter (remove-if-not filter candidates) candidates))
         (sorted (stable-sort (copy-list eligible) comparator))
         (n (min k (length sorted)))
         (protected (subseq sorted (- (length sorted) n))))
    (remove-if (lambda (p) (member p protected)) candidates)))

(defun %evict-keyed-netgroup (peer)
  "A per-node-secret keying of the peer's netgroup (Core nKeyedNetGroup). The
SECRET is what makes the netgroup protection unpredictable: without it an
attacker knows which groups sort first and can arrange to be outside them."
  (let ((group (or (bl.net:ip-netgroup
                    (bl.net:peer-address peer))
                   "_")))
    (sxhash (cons *eviction-netgroup-secret* group))))

(defvar *eviction-netgroup-secret* (random most-positive-fixnum)
  "Per-process secret behind %EVICT-KEYED-NETGROUP; Core derives its equivalent
from the node's own random key.")

(defun %evict-disadvantaged-network (peer)
  "Which of Core's four disadvantaged networks PEER belongs to, or NIL
(eviction.cpp:118-119): CJDNS, I2P, localhost, onion. These \"tend to be
otherwise disadvantaged under our eviction criteria\" — they are higher-latency,
so they lose the ping pass, and inbound onion peers all share the loopback
netgroup, so they lose the netgroup pass too."
  (cond ((bl.net:peer-inbound-onion peer) :onion)
        (t (multiple-value-bind (net bytes)
               (bl.net:parse-network-address
                (bl.net:peer-address peer))
             (declare (ignore bytes))
             (case net
               (:cjdns :cjdns)
               (:i2p :i2p)
               (:torv3 :onion)
               (t (when (bl.net:loopback-address-p
                         (bl.net:peer-address peer))
                    :local)))))))

(defun %evict-protect-by-ratio (candidates)
  "Core ProtectEvictionCandidatesByRatio (eviction.cpp:104-176).

Protects the half of the remaining candidates connected longest, and reserves
up to half of THAT (a quarter of the candidates) for the four disadvantaged
networks — giving the network with the FEWEST candidates first claim on unused
slots, so a single onion peer is not crowded out by a dozen I2P ones.

This replaces an ad-hoc onion exemption that predated it here. The exemption
worked for the case it was written for — every inbound onion peer shares the
loopback netgroup, so two of them were automatically the largest group and one
was evicted on every admission — but it protected onion peers absolutely rather
than proportionally, so an all-onion inbound set could not make room at all."
  (let* ((initial (length candidates))
         (total-protect (floor initial 2))
         (max-by-network (floor total-protect 2))
         (num-protected 0)
         (remaining candidates)
         ;; Counts per network, fewest first: Core sorts ascending so the
         ;; scarcest network gets first claim on slots the others leave.
         (networks (list :cjdns :i2p :local :onion))
         (counts (mapcar (lambda (net)
                           (cons net (count net candidates
                                            :key #'%evict-disadvantaged-network)))
                         networks)))
    (setf counts (stable-sort counts #'< :key #'cdr))
    (loop while (< num-protected max-by-network)
          do (let ((live (count-if #'plusp counts :key #'cdr)))
               (when (zerop live) (return))
               (let* ((left (- max-by-network num-protected))
                      (per-network (max 1 (floor left live)))
                      (protected-any nil))
                 (dolist (entry counts)
                   (when (plusp (cdr entry))
                     (let* ((net (car entry))
                            (before (length remaining))
                            (after (%evict-erase-last-k
                                    remaining
                                    (lambda (a b)
                                      (< (bl.net:peer-connect-time a)
                                         (bl.net:peer-connect-time b)))
                                    per-network
                                    (lambda (p) (eq net (%evict-disadvantaged-network p))))))
                       (setf remaining after)
                       (let ((delta (- before (length remaining))))
                         (when (plusp delta)
                           (setf protected-any t)
                           (incf num-protected delta)
                           (decf (cdr entry) delta)
                           (when (>= num-protected max-by-network) (return)))))))
                 (unless protected-any (return)))))
    ;; Whatever is left of the half goes to the longest-connected.
    (%evict-erase-last-k remaining
                         (lambda (a b)
                           (> (bl.net:peer-connect-time a)
                              (bl.net:peer-connect-time b)))
                         (max 0 (- total-protect num-protected)))))

(defun select-inbound-peer-to-evict (inbound)
  "Core SelectNodeToEvict (eviction.cpp:178-240), pass for pass. Returns the
peer to evict, or NIL when every candidate is protected.

The order is load-bearing and is Core's: noban, then the five \"has done
something useful\" passes with Core's own k values, then the ratio reserve,
then prefer-evict, then the most-populous netgroup, youngest first.

Ours previously ran four passes at k=4 apiece with no netgroup pass, no
block-relay-only pass, no noban protection, and an onion exemption standing in
for the ratio reserve."
  (let ((candidates inbound))
    ;; ProtectNoBanConnections (eviction.cpp:181). Only possible since net
    ;; permissions landed; a noban peer is never evicted for any reason.
    (setf candidates
          (remove-if (lambda (p)
                       (bl.net:peer-has-permission-p
                        p bl.net:+perm-noban+))
                     candidates))
    ;; ProtectOutboundConnections is implicit: INBOUND is inbound-only.
    (setf candidates (%evict-erase-last-k candidates
                                          (lambda (a b)
                                            (< (%evict-keyed-netgroup a)
                                               (%evict-keyed-netgroup b)))
                                          +evict-protect-netgroup+))
    ;; Lowest MINIMUM ping, not the latest sample: an attacker can inflate a
    ;; recent sample at will but cannot lower a minimum without being closer.
    (setf candidates (%evict-erase-last-k
                      candidates
                      (lambda (a b)
                        (flet ((ping (p)
                                 (let ((l (bl.net:peer-min-ping-latency p)))
                                   (if (plusp l) l most-positive-fixnum))))
                          (> (ping a) (ping b))))
                      +evict-protect-min-ping+))
    (setf candidates (%evict-erase-last-k
                      candidates
                      (lambda (a b)
                        (< (bl.net:peer-last-tx-time a)
                           (bl.net:peer-last-tx-time b)))
                      +evict-protect-tx+))
    ;; Block-relay-only peers that have given us blocks: Core filters this pass
    ;; to non-tx-relay peers so the slots cannot be taken by ordinary peers
    ;; that happen to have relayed a block.
    (setf candidates (%evict-erase-last-k
                      candidates
                      (lambda (a b)
                        (< (bl.net:peer-last-block-time a)
                           (bl.net:peer-last-block-time b)))
                      +evict-protect-block-relay-only+
                      (lambda (p)
                        (not (bl.net:peer-relays-txs-p p)))))
    (setf candidates (%evict-erase-last-k
                      candidates
                      (lambda (a b)
                        (< (bl.net:peer-last-block-time a)
                           (bl.net:peer-last-block-time b)))
                      +evict-protect-block+))
    (setf candidates (%evict-protect-by-ratio candidates))
    (when (null candidates)
      (return-from select-inbound-peer-to-evict nil))
    ;; Peers preferred for eviction, if any, are considered alone — but only
    ;; AFTER the passes above, since a peer that is genuinely the best by other
    ;; criteria should survive regardless (Core's own comment, :215-217).
    ;; Core's prefer_evict is set for a discouraged peer, which is exactly what
    ;; EVICT-DISCOURAGED-INBOUND already drops first; reaching here means none
    ;; was found, so this arm normally finds none either. It stays because the
    ;; two paths can disagree: a peer discouraged BETWEEN the two calls is
    ;; still preferred here.
    (let ((preferred (remove-if-not
                      (lambda (p)
                        (bl.net:peer-discouraged-p
                         (bl.net:peer-address p)))
                      candidates)))
      (when preferred (setf candidates preferred)))
    ;; Finally: the netgroup with the most connections, youngest member first.
    (let ((groups (make-hash-table :test 'equal)))
      (flet ((grp (p) (or (bl.net:ip-netgroup
                           (bl.net:peer-address p))
                          "_")))
        (dolist (p candidates) (incf (gethash (grp p) groups 0)))
        (first (stable-sort
                (copy-list candidates)
                (lambda (a b)
                  (let ((ga (gethash (grp a) groups 0))
                        (gb (gethash (grp b) groups 0)))
                    (if (/= ga gb)
                        (> ga gb)
                        (> (bl.net:peer-connect-time a)
                           (bl.net:peer-connect-time b)))))))))))

(defun evict-least-valuable-inbound (node)
  "At inbound capacity with no discouraged peer to drop, evict the least
valuable inbound peer so a new connection can take the slot — stopping an
attacker from filling inbound slots with cheap, sticky connections. Returns T
if a peer was evicted.

The selection is SELECT-INBOUND-PEER-TO-EVICT, which is Core's
AttemptToEvictConnection pass for pass."
  (bt:with-recursive-lock-held ((node-lock node))
    (let ((inbound (remove-if-not #'bl.net:peer-inbound
                                  (node-peers node))))
      (when (cdr inbound)               ; need >1 so something stays protected
        (let ((victim (select-inbound-peer-to-evict inbound)))
          (when victim
            (log-info "Evicting least-valuable inbound peer ~A to admit a new connection"
                      (bl.net:peer-address victim))
            (setf (node-peers node) (remove victim (node-peers node)))
            (bl.net:disconnect-peer victim)
            t))))))

(defun inbound-connection-allowed-p (node host)
  "Admission check for a freshly-accepted inbound connection from HOST,
before any handshake work (Core CConnman::CreateNodeFromAcceptedSocket,
net.cpp:1801-1813): a banned address is always dropped; a discouraged
address is dropped only when the inbound slots are (almost) full; and no
connection is admitted while the hand-off queue is already full. Returns T,
or (VALUES NIL REASON) when the connection must be dropped.

The backlog arm matters because *MAX-INBOUND-CONNECTIONS* is otherwise enforced only
at MERGE time, by the sync thread. Accepted peers hold a socket while they wait
in PENDING-INBOUND-PEERS, so anything that stalls that thread turns every new
connection into a leaked descriptor — the live wedge of 2026-08-16 accumulated
751 sockets in CLOSE-WAIT this way. Counting the queue bounds the damage at
twice the inbound cap no matter what the rest of the node is doing."
  ;; Ban check first and lock-free: a connect flood is exactly when the listener
  ;; must not contend with the sync thread and RPC readers for the node lock.
  (cond
    ((bl.net:peer-banned-p host)
     (values nil :banned))
    ((>= (bt:with-recursive-lock-held ((node-lock node))
           (length (node-pending-inbound-peers node)))
         *max-inbound-connections*)
     (values nil :backlog))
    ((and (bl.net:peer-discouraged-p host)
          (>= (1+ (bt:with-recursive-lock-held ((node-lock node))
                    (count-inbound-peers node)))
              *max-inbound-connections*))
     (values nil :discouraged))
    (t t)))

(defun reconcile-coins-db-best-block (node)
  "Make chainstate.dat agree with where the coins actually are.

Returns :match, :reconciled, :unresolvable, :unrecorded (a chainstate written
before the coins DB carried the pointer) or NIL when there is nothing to
compare.

The coins DB records the block its UTXO state corresponds to, moved with the
coins themselves, so a disagreement with chainstate.dat is not ambiguous: the
pointer is the fact and the tip record is the stale copy. THE COINS WIN. That
direction is not a preference — a UTXO set cannot be reconstructed from the tip
record, while the tip record is one hash we can rewrite, and the same choice is
what the older in-transition recovery already makes by probing.

Core reaches the same end differently: DB_HEAD_BLOCKS gives it a RANGE, so
ReplayBlocks must roll the coins to one end of it (validation.cpp:4812-4889).
Our pointer is exact, so there is nothing to roll — we move the cheap record to
the expensive one and let normal sync re-validate the gap.

Unresolvable means the coins name a block we have no index entry for, which no
amount of local reasoning can fix; the caller should treat that as fatal rather
than proceed on a tip we cannot place."
  (let* ((chainstate (node-chain-state node))
         (view (and chainstate
                    (bl.store:chain-state-coins-view chainstate))))
    (unless (typep view 'bl.store:coins-view-cache)
      (return-from reconcile-coins-db-best-block nil))
    (let ((recorded (bl.store:coins-view-db-best-block
                     (bl.store:coins-view-cache-base view)))
          (tip (bl.store:best-block-hash chainstate)))
      (cond
        ((null recorded)
         (log-info "Coins DB has no best-block pointer yet; it will be written on the next flush")
         :unrecorded)
        ((and tip (equalp recorded tip))
         :match)
        (t
         (let ((entry (bl.store:get-block-index-entry chainstate recorded)))
           (cond
             ((null entry)
              (log-error "Coins DB best-block ~A is not in the block index; cannot place the UTXO set"
                         (bl.crypto:bytes-to-hex
                          (bl.crypto:reverse-bytes recorded)))
              :unresolvable)
             (t
              (let ((coins-height (bl.store:block-index-entry-height entry))
                    (tip-height (bl.store:current-height chainstate)))
                (log-warn "UTXO set is at height ~D (~A) but chainstate.dat records tip height ~D; a reorg or flush was interrupted"
                          coins-height
                          (bl.crypto:bytes-to-hex
                           (bl.crypto:reverse-bytes recorded))
                          tip-height)
                (setf (bl.store::chain-state-best-block-hash chainstate)
                      (copy-seq recorded)
                      (bl.store::chain-state-best-height chainstate)
                      coins-height)
                (bl.store:save-state chainstate :in-transition nil)
                (log-warn "Recovered: chainstate.dat moved to the UTXO set's own block; sync will re-validate the gap")
                :reconciled)))))))))


(defun run-inbound-listener (node &key (socket (node-listener-socket node)) onion)
  "Accept inbound connections on SOCKET, handshake each, and hand the ready
peer to the sync thread via pending-inbound-peers. Runs until the node stops.
The handshake runs inline (serial accept) with a short timeout, so a silent
peer stalls the loop only briefly; a thread pool is a future refinement.
ONION marks this as the onion-service listener: its connections arrive from
the local Tor daemon, so the peers are tagged inbound-onion (their true
network is :torv3, Core CNode::m_inbound_onion)."
  (loop while (node-running node)
        do (handler-case
               ;; setnetworkactive off: don't accept inbound connections.
               (if (not (node-network-active node))
                   (sleep 1)
               (let ((conn (bl.net:accept-connection
                            socket :timeout 1)))
                 (when conn
                   ;; Banned/discouraged admission gate BEFORE the handshake
                   ;; (Core drops these in CreateNodeFromAcceptedSocket,
                   ;; net.cpp:1801-1813).
                   (multiple-value-bind (allowed reason)
                       (inbound-connection-allowed-p
                        node (bl.net:connection-host conn))
                     (if (not allowed)
                         (progn
                           (log-info "Inbound connection from ~A dropped (~(~A~))"
                                     (bl.net:connection-host conn)
                                     reason)
                           (bl.net:close-connection conn))
                         (let ((peer (bl.net:make-inbound-peer
                                      conn (bl.net:connection-host conn)
                                      :inbound-onion onion)))
                           (if (bl.net:perform-inbound-handshake peer)
                               (progn
                                 (bl.net:send-post-handshake-messages peer)
                                 (bl.net:send-compact-block-negotiation peer)
                                 (bt:with-recursive-lock-held ((node-lock node))
                                   (push peer (node-pending-inbound-peers node)))
                                 (log-info "Inbound~:[~; onion~] peer ~A (~A) handshake complete"
                                           onion
                                           (bl.net:peer-address peer)
                                           (bl.net:peer-user-agent peer)))
                               (bl.net:disconnect-peer peer))))))))
             (error (c)
               (log-debug "Inbound accept/handshake error: ~A" c)))))

(defun start-inbound-listener (node bind)
  "Open the listening socket and spawn the accept thread. No-op (logged) if the
port can't be bound."
  (let ((sock (bl.net:open-listener bind (listen-port (node-network node)))))
    (if (null sock)
        (log-warn "Inbound listening disabled: could not bind ~A:~D"
                  bind (listen-port (node-network node)))
        (progn
          (setf (node-listener-socket node) sock)
          (setf (node-listener-thread node)
                (bt:make-thread (lambda () (run-inbound-listener node))
                                :name "bitcoin-inbound-listener"))
          (log-info "Listening for inbound peers on ~A:~D"
                    bind (listen-port (node-network node)))))))

(defun onion-listen-port (node)
  "The local port Tor forwards inbound onion connections to: the listen
port + 1 (Core's default_bind_port_onion, init.cpp:2118 — -port shifts it
too — and DefaultOnionServiceTarget)."
  (1+ (listen-port (node-network node))))

(defun start-onion-listener (node)
  "Open the onion-service target listener on 127.0.0.1:(port+1) and spawn its
accept thread. Bound to loopback only — connections come exclusively from the
local Tor daemon; the bind is never advertised (Core BF_DONT_ADVERTISE on
onion binds). No-op (logged) if the port can't be bound; torcontrol still
runs, matching Core, where a failed onion bind and the control thread are
independent."
  (let* ((port (onion-listen-port node))
         (sock (bl.net:open-listener "127.0.0.1" port)))
    (if (null sock)
        (log-warn "Onion inbound listening disabled: could not bind 127.0.0.1:~D" port)
        (progn
          (setf (node-onion-listener-socket node) sock)
          (setf (node-onion-listener-thread node)
                (bt:make-thread (lambda ()
                                  (run-inbound-listener node :socket sock :onion t))
                                :name "bitcoin-onion-listener"))
          (log-info "Listening for inbound onion peers on 127.0.0.1:~D" port)))))

(defun broadcast-transaction-to-peers (node txid)
  "Queue announcements of the in-mempool TXID to every connected
relay-capable peer — the broadcast tail of Core's BroadcastTransaction
(node/transaction.cpp:131-135 -> PeerManager::InitiateTxBroadcastToAll).
Nothing is sent directly: the sync loop's Poisson flusher
(flush-tx-announcements) drains the queues, respecting each peer's
wtxid-relay preference, fRelay, and BIP133 feefilter. Under the node lock
because RPC handler threads call this while the sync thread owns the same
queues. Returns T when the tx was found in the mempool and queued."
  (bt:with-recursive-lock-held ((node-lock node))
    (bl.net:announce-mempool-tx
     (node-peers node) (node-mempool node) txid)))

(defun load-mempool-from-disk
    (node &optional (path (bl.mp:mempool-dat-path (node-data-directory node)))
     &key (apply-unbroadcast t) (apply-fee-delta-priority t) (use-current-time nil))
  "Load a mempool.dat-format file through the normal acceptance path (Core
LoadMempool): prioritisation deltas first (so fee policy sees them), then per-tx
validation against the current UTXO set — stale entries (spent inputs, reorged
context) simply fail and are dropped. Entries are loaded regardless of age (no
expiry filter, unlike Core): mempool-expire prunes old entries on the next block
connection anyway. Residual deltas (txs not in the saved pool) are re-applied
last, then the saved unbroadcast set for txs that made it back into the pool
(Core node/mempool_persist.cpp:134-141) — unless APPLY-UNBROADCAST is NIL,
which is the importmempool RPC's default (Core apply_unbroadcast_set,
rpc/mempool.cpp:1115).

⚠️ The defaults here are the STARTUP ones, and all three are the OPPOSITE of
importmempool's. Core keeps two sets (node/mempool_persist.h:20-25 for the boot
load, rpc/mempool.cpp:1138-1141 for the RPC):

              startup   importmempool
  use_current_time          NIL         T
  apply_fee_delta_priority   T          NIL
  apply_unbroadcast_set      T          NIL

The reasoning is that a boot load is restoring THIS node's own mempool — it
wants the original entry times so expiry still means something, and it wants
its own prioritisation back — while importmempool is ingesting someone else's
file, where a foreign fee delta is not this operator's policy and a foreign
timestamp would misdate the entry. PATH defaults to the node's mempool.dat.
Returns
(values accepted failed residual-count) on success, or NIL if the file is
missing or corrupt."
  (when (and path (probe-file path))
      (multiple-value-bind (entries residual ok unbroadcast)
          (bl.mp:read-mempool-file path)
        (unless ok
          (log-warn "mempool file ~A unreadable or corrupt" path)
          (return-from load-mempool-from-disk nil))
        (let ((mempool (node-mempool node))
              (utxo-set (node-utxo-set node))
              (chain-state (node-chain-state node))
              (accepted 0) (failed 0) (unbroadcast-count 0)
              (total (length entries))
              (tried 0)
              (next-tenth 0))
          ;; Announce the size and report every 10% (Core mempool_persist.cpp:77-86).
          ;; Every entry is re-validated in full, so a large dump is minutes of
          ;; CPU — and this used to log nothing at all until it finished: an
          ;; 83 MB testnet4 mempool.dat took ~45 minutes of silence on the
          ;; 2026-08-16 deploy, indistinguishable from a wedge.
          (when (plusp total)
            (log-info "Loading ~D mempool transaction~:P from ~A..." total path))
          (dolist (rec entries)
            ;; Cooperative stop between transactions (Core checks m_interrupt per
            ;; tx, mempool_persist.cpp:122). Abandoning applies NEITHER the
            ;; residual deltas NOR the unbroadcast set — Core returns before
            ;; both, and half-restoring would leave prioritisation for
            ;; transactions that never came back. What was already accepted stays
            ;; in the pool and is dumped at shutdown, so the next start resumes
            ;; from a smaller file.
            (when (bl:interrupt-requested-p)
              (log-warn "Mempool import abandoned on a stop request after ~D of ~D transaction~:P (~D accepted, ~D failed); the remainder stays in ~A"
                        tried total accepted failed path)
              (return-from load-mempool-from-disk (values accepted failed 0)))
            (let* ((pct (floor (* 100 tried) total))
                   (tenth (floor pct 10)))
              (when (> tenth next-tenth)
                (setf next-tenth tenth)
                (log-info "Progress loading mempool transactions: ~D% (tried ~D, ~D remaining)"
                          pct tried (- total tried))))
            (incf tried)
            (destructuring-bind (tx entry-time delta) rec
              ;; Core overwrites the saved time with now BEFORE the fee delta
              ;; and the acceptance (mempool_persist.cpp:95-97).
              (when use-current-time
                (setf entry-time (bl.ser:get-unix-time)))
              (let ((txid (bl.ser:transaction-hash tx))
                    (height (bl.store:current-height chain-state)))
                (when (and apply-fee-delta-priority (not (zerop delta)))
                  (bl.mp:mempool-prioritise mempool txid delta))
                ;; CHAIN-STATE gates the finality/BIP68 checks — a saved tx
                ;; that is no longer minable in the next block must not
                ;; reload (Core LoadMempool goes through the full
                ;; AcceptToMemoryPool, node/mempool_persist.cpp:105).
                (multiple-value-bind (valid error fee replaced sigops)
                    ;; Core uncaches every prevout this pulled in when the
                    ;; result is not VALID (validation.cpp:851, 1787-1790):
                    ;; otherwise a stream of transactions that fail AFTER input
                    ;; fetch leaves one cache entry per distinct outpoint, with
                    ;; nothing evicting them until the next block connects.
                    (bl.store:with-coins-to-uncache (utxo-set)
                      (bl.val:validate-transaction-for-mempool
                       tx utxo-set mempool height :chain-state chain-state))
                  (declare (ignore error))
                  (cond
                    (valid
                     (if (eq :ok (bl.mp:accept-validated-tx
                                  mempool txid tx fee height
                                  :entry-time entry-time :sigops sigops
                                  :replaced replaced))
                         (incf accepted)
                         (incf failed)))
                    (t (incf failed)))))))
          ;; The residual map is gated on the same option as the per-entry
          ;; deltas (mempool_persist.cpp:128-132) — importmempool must not
          ;; import a foreign node's prioritisation by either route.
          (when apply-fee-delta-priority
            (dolist (pair residual)
              (bl.mp:mempool-prioritise mempool (car pair) (cdr pair))))
          ;; Restore the unbroadcast set for txs that were re-accepted; ids
          ;; whose tx failed to reload are dropped (mempool-add-unbroadcast's
          ;; membership gate) — Core node/mempool_persist.cpp:136-142.
          (when apply-unbroadcast
            (dolist (txid unbroadcast)
              (when (bl.mp:mempool-add-unbroadcast mempool txid)
                (incf unbroadcast-count))))
          (log-info "Imported mempool: ~D accepted, ~D failed, ~D residual deltas, ~D waiting for initial broadcast"
                    accepted failed (length residual) unbroadcast-count)
          (values accepted failed (length residual))))))

;;; --- Chainstate crash recovery -------------------------------------------
;;;
;;; do-flush is a 3-phase commit (see do-flush): Phase 1 marks chainstate.dat
;;; in-transition, Phase 2 commits the UTXO LevelDB in ONE atomic writebatch,
;;; Phase 3 clears the marker. A crash between Phase 1 and Phase 3 leaves the
;;; marker set. Because Phase 2 is a single atomic batch, the on-disk UTXO set
;;; is at EXACTLY the new tip (Phase 2 finished) or the previous committed tip
;;; (Phase 2 hadn't run) — never a torn mix. We tell the two apart by probing
;;; coinbase outputs and rewrite chainstate.dat to match the UTXO set, instead
;;; of the old "move aside and re-sync from genesis" — mirrors Bitcoin Core
;;; resolving its DB_HEAD_BLOCKS marker on startup rather than reindexing.

(defvar *pending-chainstate-recovery* nil
  "List of chainstates whose load-state reported :inconsistent, so their
recovery runs after the block store, UTXO caches, and header index are all
open. Per-chainstate: the primary and a snapshot chainstate recover
independently against their own state files and coins views.")

(defun %coinbase-committed-p (node chainstate block-hash)
  "T iff BLOCK-HASH's coinbase output 0 is an unspent coin in CHAINSTATE's
coins view. A coinbase is unspendable for +coinbase-maturity+ (100) blocks,
so once its block is committed to the UTXO set the coin is necessarily
present — and every block above the committed tip contributes no coins at
all. That makes coinbase-presence a monotone probe for 'is the UTXO set at
or past this block', with no false positives from later spends. Returns
NIL if the block isn't on disk (the block store is shared across
chainstates)."
  (let ((block (bl.store:get-block (node-block-store node) block-hash)))
    (when block
      (let* ((cb (first (bl.ser:bitcoin-block-transactions block)))
             (txid (bl.ser:transaction-hash cb)))
        (and (bl.store:get-utxo
              (bl.store:chain-state-coins-view chainstate) txid 0)
             t)))))

(defun recover-inconsistent-chainstate
    (node &optional (chain-state (node-current-chainstate node)))
  "Resolve an in-transition chainstate without a from-genesis resync.
Per-chainstate: probes CHAIN-STATE's own coins view and rewrites its own
state file (storage-suffix-named), so recovering one chainstate can never
touch another's on-disk state. The 3-phase commit semantics are unchanged.
Probes whether the recorded tip's coins were committed; if so just clears
the marker, otherwise walks back to the highest ancestor whose coins ARE
committed (the true UTXO tip) and rewrites the state file there so IBD
re-validates only the gap. A recorded tip AT genesis is an interrupted
-reindex-chainstate (see do-reindex-chainstate): the coins DB is re-wiped
and the marker cleared, resuming as an ordinary from-genesis sync. Returns
T on success, NIL if the blocks needed to resolve it aren't on disk (caller
then aborts for a resync).

For a snapshot chainstate, its base block is always treated as committed:
the populate step verified and durably flushed the whole snapshot UTXO set
before the chainstate ever existed, and its coins only move forward from
there — so both the tip==base case (nothing dirty could have been flushed)
and the walk-back floor (rewind to the base, whose coins ARE the verified
snapshot) resolve without probing blocks below the base, which are not on
disk on the snapshot side."
  (let* ((new-hash (bl.store:best-block-hash chain-state))
         (new-height (bl.store:current-height chain-state))
         (snapshot-base (bl.store:chain-state-from-snapshot-blockhash
                         chain-state)))
    (flet ((committed-p (hash)
             (or (and snapshot-base (equalp hash snapshot-base))
                 (%coinbase-committed-p node chain-state hash))))
      (cond
        ((null new-hash)
         (log-error "Chainstate recovery: no recorded tip to recover from")
         nil)
        ;; Recorded tip = genesis: an interrupted -reindex-chainstate.
        ;; do-reindex-chainstate rewinds chainstate.dat to genesis (marker
        ;; set) before wiping the coins DB, so this state means the wipe or
        ;; the replay's first flush never completed. Nothing SHOULD be
        ;; committed at genesis — whatever the coins DB holds is refuse from
        ;; the interrupted wipe — so the one consistent resolution is an
        ;; empty set: re-wipe and clear the marker. The node then resumes as
        ;; an ordinary from-genesis sync (or rebuilds from stored blocks if
        ;; -reindex-chainstate is passed again after IBD re-covers the tip).
        ((and (not snapshot-base)
              (equalp new-hash (bl.store::chain-state-genesis-hash
                                chain-state)))
         (let ((view (bl.store:chain-state-coins-view chain-state)))
           (when (typep view 'bl.store:coins-view-cache)
             (let ((erased (bl.store:coins-view-cache-wipe view)))
               (when (plusp erased)
                 (log-info "Chainstate recovery: erased ~D leftover coin~:P from the interrupted wipe"
                           erased)))))
         (bl.store:save-state chain-state :in-transition nil)
         (log-warn "Chainstate recovery: interrupted reindex-chainstate; UTXO set reset to empty at genesis (chain will re-sync)")
         t)
        ;; Phase 2 committed the new tip — chainstate.dat already holds it,
        ;; just drop the marker.
        ((committed-p new-hash)
         (bl.store:save-state chain-state :in-transition nil)
         (log-info "Chainstate recovery: UTXO set already at recorded tip h=~D; marker cleared"
                   new-height)
         t)
        ;; UTXO set is behind: find the real tip by walking back.
        (t
         (let ((entry (bl.store:get-block-index-entry chain-state new-hash)))
           (loop while entry
                 do (setf entry (bl.store:block-index-entry-prev-entry entry))
                 until (or (null entry)
                           (committed-p
                            (bl.store:block-index-entry-hash entry))))
           (cond
             (entry
              (let ((h (bl.store:block-index-entry-height entry))
                    (hash (bl.store:block-index-entry-hash entry)))
                ;; pruned-height is left as recorded — pruning is monotone and
                ;; lags the tip by the whole block window, so it is far below
                ;; this rewind point and those files are gone regardless.
                (setf (bl.store::chain-state-best-block-hash chain-state) hash
                      (bl.store::chain-state-best-height chain-state) h)
                (bl.store:save-state chain-state :in-transition nil)
                (log-warn "Chainstate recovery: UTXO set at h=~D (recorded tip h=~D); rewound chainstate.dat ~D block~:P, will re-validate the gap"
                          h new-height (- new-height h))
                t))
             (t
              (log-error "Chainstate recovery: no committed ancestor found on disk (blocks pruned below the UTXO tip?); resync required")
              nil))))))))

;;; --- Assumeutxo snapshot chainstate lifecycle ------------------------------
;;;
;;; Core model (validation.cpp ActivateSnapshot/AddChainstate + node/
;;; chainstate.cpp LoadChainstate): a verified snapshot becomes a SECOND
;;; chainstate with storage suffix "_snapshot", status :unvalidated (never
;;; persisted — re-derived every startup), sharing the block index / block
;;; store / undo storage with the primary. The primary is retargeted at the
;;; snapshot base and becomes the HISTORICAL chainstate, re-deriving history
;;; in the background while the snapshot chainstate follows the network tip.
;;; The only persistent marker is chainstate_snapshot/base_blockhash.
;;;
;;; The streaming/verification half of activation (Core
;;; PopulateAndValidateSnapshot) lives with the loadtxoutset RPC
;;; (rpc/methods.lisp), which parses the snapshot format; the chainstate
;;; mechanics live here.

(defun call-with-sync-paused (node thunk)
  "Run THUNK with the sync thread's IBD loops paused — the coarse equivalent
of Core holding cs_main across snapshot activation. Requests an IBD stop,
waits (bounded) for the in-progress sync-blockchain pass to unwind, runs
THUNK, then clears the stop request so the next sync cycle resumes against
the (possibly changed) chainstate arrangement. A no-op without a live sync
thread (tests, :sync nil nodes)."
  (if (and (node-sync-thread node)
           (bt:thread-alive-p (node-sync-thread node)))
      (progn
        (bl.net:request-ibd-stop)
        (loop repeat 600                ; <= 120s; the IBD loops poll the flag
              while (node-syncing node)
              do (sleep 0.2))
        (when (node-syncing node)
          (log-warn "Sync pass did not pause within 120s; proceeding with snapshot activation anyway"))
        (unwind-protect (funcall thunk)
          (bl.net:reset-ibd-stop)))
      (funcall thunk)))

(defun %make-snapshot-chainstate (node base-hash)
  "The snapshot chain-state struct for BASE-HASH: status :unvalidated (Core
derives it from from_snapshot_blockhash, validation.cpp:1868 — never
persisted), storage suffix \"_snapshot\", and the block index SHARED with
the primary chainstate (Core keeps it in m_blockman, outside any
chainstate). Used by both activation (create-snapshot-chainstate) and
startup re-detection (load-snapshot-chainstate)."
  (let ((primary (node-current-chainstate node)))
    (bl.store:make-chain-state
     :base-path (node-data-directory node)
     :genesis-hash (bl.store::chain-state-genesis-hash primary)
     :block-index (bl.store::chain-state-block-index primary)
     :from-snapshot-blockhash (copy-seq base-hash)
     :assumeutxo-status :unvalidated
     :storage-suffix "_snapshot")))

(defun create-snapshot-chainstate (node base-hash)
  "Construct an :unvalidated snapshot chainstate for BASE-HASH with a fresh
coins LevelDB at <data-dir>/chainstate_snapshot/ (Core ActivateSnapshot's
Chainstate construction + InitCoinsDB). Stale on-disk leftovers from an
aborted or unadoptable earlier activation are removed first — startup
adopts any intact snapshot chainstate, so anything still here is refuse.
The caller owns cleanup on failure (abort-snapshot-chainstate)."
  (let ((snap (%make-snapshot-chainstate node base-hash)))
    (when (bl.store:find-assumeutxo-chainstate-dir
           (node-data-directory node))
      (log-warn "[snapshot] removing stale snapshot chainstate leftovers before activation")
      (bl.store:delete-snapshot-chainstate-files
       (node-data-directory node)))
    (bl.store:open-chainstate-coins-view snap)
    snap))

(defun abort-snapshot-chainstate (node snap)
  "Tear down SNAP mid-activation (Core cleanup_bad_snapshot): close its coins
DB (releasing the LevelDB lock) and delete its on-disk footprint. Never
signals — this runs on the activation failure path."
  ;; Core's cleanup_bad_snapshot rebalances first (validation.cpp:5697) —
  ;; the failed activation must not leave a split cache allocation behind.
  (ignore-errors (maybe-rebalance-caches node))
  (bl.store:close-chainstate-coins-view snap)
  (ignore-errors
    (bl.store:delete-snapshot-chainstate-files
     (node-data-directory node)))
  nil)

(defun add-snapshot-chainstate (node snap)
  "Adopt a populated, verified snapshot chainstate (Core AddChainstate,
validation.cpp:6189-6206): retarget the previously-current chainstate at the
snapshot base — making it the historical chainstate — and append SNAP, which
select-current-chainstate then returns as the new current chainstate.

The mempool needs no explicit hand-off (Core swaps the pointer): ours lives
on the node and every mempool call site reads the CURRENT chainstate's coins
view, which this swap redirects. Callers must have verified the mempool is
empty first (Core asserts it). Core's PopulateBlockIndexCandidates has no
equivalent here — our fork choice is per-block (activate-block) and the
historical chainstate's candidate filtering is the target guard there."
  (let* ((prev (node-current-chainstate node))
         (base-hash (bl.store:chain-state-from-snapshot-blockhash snap))
         (base-entry (bl.store:get-block-index-entry prev base-hash)))
    (assert (eq (bl.store:chain-state-assumeutxo-status prev) :validated))
    (assert (null (bl.store:chain-state-target-blockhash prev)))
    (assert base-entry)
    (bl.store:set-chainstate-target prev base-entry)
    (bt:with-recursive-lock-held ((node-lock node))
      (setf (node-chainstates node)
            (append (node-chainstates node) (list snap))))
    ;; Split the coins-cache budget across the two chainstates (Core calls
    ;; MaybeRebalanceCaches at the end of ActivateSnapshot,
    ;; validation.cpp:5745).
    (maybe-rebalance-caches node)
    (log-info "[snapshot] successfully activated snapshot ~A: current chainstate now at height ~D following the network tip; historical chainstate (h=~D) re-derives history toward the base in the background"
              (bl.crypto:bytes-to-hex base-hash)
              (bl.store:current-height snap)
              (bl.store:current-height prev))
    snap))

(defun load-snapshot-chainstate (node)
  "Detect and re-adopt a persisted snapshot chainstate at startup (Core
LoadAssumeutxoChainstate, validation.cpp:6170-6187, in node/chainstate.cpp
LoadChainstate ordering). The chainstate_snapshot/ dir plus its
base_blockhash marker are the only persistent evidence; assumeutxo-status is
re-derived as :unvalidated (never persisted). Must run after the primary
chainstate's header index is loaded — the base entry has to resolve — and
before crash-recovery resolution (a torn snapshot flush joins
*pending-chainstate-recovery*). Returns the snapshot chainstate or NIL."
  (let* ((data-dir (node-data-directory node))
         (dir (bl.store:find-assumeutxo-chainstate-dir data-dir)))
    (when dir
      (let* ((base-hash (bl.store:read-snapshot-base-blockhash dir))
             (primary (node-current-chainstate node))
             (base-entry (and base-hash
                              (bl.store:get-block-index-entry
                               primary base-hash))))
        (cond
          ((null base-hash)
           (log-warn "[snapshot] snapshot chainstate dir is malformed! no base blockhash file exists at path ~A. Try deleting ~A and calling loadtxoutset again"
                     (namestring (bl.store:snapshot-base-blockhash-path dir))
                     (namestring dir))
           nil)
          ((null base-entry)
           ;; Header index lost/regressed below the base. Leave the snapshot
           ;; chainstate on disk and run single-chainstate this boot; once
           ;; headers re-cover the base, the next restart adopts it.
           (log-warn "[snapshot] snapshot base block ~A is not in the header index; not loading the snapshot chainstate this run"
                     (bl.crypto:bytes-to-hex base-hash))
           nil)
          (t
           (log-info "[snapshot] detected active snapshot chainstate (~A) - loading"
                     (namestring dir))
           (let ((snap (%make-snapshot-chainstate node base-hash))
                 (base-height (bl.store:block-index-entry-height base-entry)))
             ;; Tip from chainstate_snapshot.dat; a torn flush defers to the
             ;; per-chainstate recovery pass; a missing .dat means activation
             ;; completed (dir + marker prove the populate did) but the first
             ;; save-state never landed — start the chainstate at its base.
             (case (bl.store:load-state snap)
               ((:inconsistent)
                (log-warn "[snapshot] snapshot chainstate in-transition (flush interrupted); will attempt automatic recovery after storage init")
                (push snap *pending-chainstate-recovery*))
               ((t) nil)
               ((nil)
                (log-warn "[snapshot] no chainstate_snapshot.dat; starting the snapshot chainstate at its base (h=~D)" base-height)
                (bl.store:update-chain-tip
                 snap (copy-seq base-hash) base-height)))
             ;; The recorded tip must resolve in the shared header index;
             ;; otherwise fall back to the base (blocks above it re-sync).
             (let ((tip-hash (bl.store:best-block-hash snap)))
               (unless (and tip-hash
                            (bl.store:get-block-index-entry primary tip-hash))
                 (log-warn "[snapshot] snapshot chainstate tip not in the header index; resetting to the base (h=~D)" base-height)
                 (bl.store:update-chain-tip
                  snap (copy-seq base-hash) base-height)))
             ;; Open its coins DB (chainstate_snapshot/).
             (bl.store:open-chainstate-coins-view snap)
             ;; Retarget the primary (it becomes the historical chainstate)
             ;; and adopt the snapshot chainstate as current.
             (bl.store:set-chainstate-target primary base-entry)
             (setf (node-chainstates node)
                   (append (node-chainstates node) (list snap)))
             ;; Split the coins-cache budget across the re-adopted pair (Core
             ;; LoadChainstate's MaybeRebalanceCaches, node/chainstate.cpp:146).
             (maybe-rebalance-caches node)
             (log-info "[snapshot] switching active chainstate to the snapshot chainstate (tip h=~D); historical chainstate at h=~D targets the base at h=~D"
                       (bl.store:current-height snap)
                       (bl.store:current-height primary)
                       base-height)
             snap)))))))

;;;; Shutdown coordination (Core's StartShutdown / WaitForShutdown split)
;;;;
;;;; Every internal stop path — the `stop` RPC, -stopatheight, the low-disk
;;;; abort, a snapshot that fails background validation — runs on a NON-main
;;;; thread, while the supervisor's watchdog runs on the main thread and exits
;;;; the process shortly after it sees the node stop running. Calling stop-node
;;;; from those threads is therefore a race with the process exit: stop-node
;;;; clears node-running FIRST and does the chainstate flush, mempool.dat,
;;;; peers.dat, banlist and wallet best-block markers AFTER, and sb-ext:exit
;;;; unwinds other threads without waiting for them. At an idle tip the whole
;;;; sequence takes about as long as one watchdog tick (a coin flip); mid-block,
;;;; or with a large dirty coins cache, the kill is certain.
;;;;
;;;; Core has exactly this split: StartShutdown() only sets a token
;;;; (shutdown/shutdown.cpp), the main thread's WaitForShutdown() returns, and
;;;; Shutdown() then runs the entire teardown on the MAIN thread
;;;; (bitcoind.cpp:180-193). We mirror it: internal paths call
;;;; request-node-shutdown, run-node-watchdog (the main thread) runs stop-node
;;;; itself and only exits once *shutdown-complete* is set — stop-node's final
;;;; act.

(defconstant +node-exit-clean+ 0
  "Process exit code for a deliberate, completed stop (`stop` RPC, SIGTERM,
-stopatheight). The supervisor must NOT respawn on this.")

(defconstant +node-exit-error+ 1
  "Process exit code for a deterministic failure (bad config, unrecoverable
chainstate, disk space): respawning immediately just spins on it.")

(defconstant +node-exit-watchdog+ 7
  "Process exit code when the node stopped running without being asked to
(fatal snapshot, crashed sync thread): the supervisor should respawn.")

(defvar *node-starting* nil
  "T while start-node is still building the node. The SIGTERM handler is
installed at the START of start-node (Core AppInitBasicSetup), so a stop can
arrive while there is no node to tear down and no watchdog yet — in that window
the handler only registers the request; see install-shutdown-handler.")

(defvar *shutdown-request* nil
  "NIL, or the pending shutdown request as (REASON . EXIT-CODE). Written
exactly once per run by request-node-shutdown, via CAS rather than a lock so
it is safe to call from a signal handler (a lock could deadlock against the
thread the signal interrupted). One cell, so a reader never sees a reason
without its exit code.")

;;;; The shutdown token pipe (Core util::SignalInterrupt, util/signalinterrupt.cpp)
;;;;
;;;; Core's whole SIGTERM handler is `(*g_shutdown)()`, and that call is an
;;;; atomic exchange on a flag plus, only if it won, one write() of a single
;;;; byte to a pipe. The comment above it states the rule this file now follows:
;;;; "This must be reentrant and safe for calling in a signal handler, so using
;;;; a condition variable is not safe."
;;;;
;;;; Ours used to do considerably more from inside the handler — format to
;;;; *error-output*, log-info (taking the log mutex), and on the REPL path
;;;; bt:make-thread and the entire stop-node teardown. That is why *LOG-LOCK*
;;;; had to be recursive: a signal delivered to a thread already inside an emit
;;;; would otherwise deadlock on its own lock. With the handler reduced to
;;;; Core's two operations, none of that is reachable and the lock is a plain
;;;; one again, as Core's StdMutex is.
;;;;
;;;; write(2) on a pipe is async-signal-safe (POSIX.1 async-signal-safe list);
;;;; a mutex acquisition is not. The byte's only job is to WAKE a servicer —
;;;; the flag is what carries the request.

(defvar *shutdown-servicer-thread* nil
  "The thread blocked in %RUN-SHUTDOWN-SERVICER, or NIL. Its existence is what
lets REQUEST-NODE-SHUTDOWN stop spawning a thread per request.")

(defvar *shutdown-pipe-read* nil "Read end of the shutdown token pipe, or NIL.")
(defvar *shutdown-pipe-write* nil "Write end of the shutdown token pipe, or NIL.")

(defvar *shutdown-token-buffer*
  (make-array 1 :element-type '(unsigned-byte 8) :initial-element (char-code #\x))
  "Preallocated one-byte buffer for the token write. Allocated ONCE, at load
time: a signal handler must not cons, and Core's TokenWrite writes a stack
byte for the same reason.")

(defvar *signal-shutdown-request* (cons "SIGTERM/SIGINT" +node-exit-clean+)
  "Preallocated (REASON . EXIT-CODE) cell the signal handler CASes into
*SHUTDOWN-REQUEST*. Building the cons inside the handler would allocate, and an
allocation can land in the middle of the GC the signal interrupted.")

(defun %open-shutdown-pipe ()
  "Create the token pipe if it does not exist yet. Idempotent."
  #+sbcl
  (unless *shutdown-pipe-write*
    (multiple-value-bind (r w) (sb-posix:pipe)
      (setf *shutdown-pipe-read* r
            *shutdown-pipe-write* w)))
  *shutdown-pipe-write*)

(defun %write-shutdown-token ()
  "Write the single wake-up byte. Async-signal-safe: no allocation, no lock,
no stream. Core SignalInterrupt::operator()'s TokenWrite."
  #+sbcl
  (let ((fd *shutdown-pipe-write*))
    (when fd
      ;; The return value is intentionally ignored, for the reason Core gives
      ;; in HandleSIGTERM: there is no better way to handle a failure here.
      (ignore-errors
       (sb-sys:with-pinned-objects (*shutdown-token-buffer*)
         (sb-posix:write fd (sb-sys:vector-sap *shutdown-token-buffer*) 1)))))
  nil)

(defun %await-shutdown-token ()
  "Block until a token arrives. Core SignalInterrupt::wait()."
  #+sbcl
  (let ((fd *shutdown-pipe-read*)
        (buf (make-array 1 :element-type '(unsigned-byte 8))))
    (when fd
      (sb-sys:with-pinned-objects (buf)
        (loop until (eql 1 (ignore-errors
                            (sb-posix:read fd (sb-sys:vector-sap buf) 1)))))))
  t)

(defvar *shutdown-complete* nil
  "Set by stop-node as its FINAL act, after the chainstate flush, mempool.dat,
peers.dat, banlist and wallet markers are on disk. The watchdog waits for this
before exiting the process; a concurrent stop-node caller waits on it too.")

(defvar *stop-node-in-progress* nil
  "CAS latch: T while one thread is inside stop-node's teardown. stop-node is
otherwise not concurrent-safe — two overlapping runs would both drive
%flush-chainstate through the same fixed chainstate.dat.tmp path and
double-close the same LevelDB handles.")

(defvar *shutdown-watchdog-running* nil
  "T while run-node-watchdog polls on the main thread. Read from other threads,
so it is SETF on the global (a LET binding would be invisible to them).")

(defun request-node-shutdown (reason &key (exit-code +node-exit-clean+))
  "Ask the node to shut down; the MAIN thread does the actual work (Core
StartShutdown). REASON is logged; EXIT-CODE is what the supervisor will see
(+node-exit-clean+ / -error+ / -watchdog+). Returns T if this call registered
the request, NIL if a shutdown was already pending (first caller wins).

Without a main-thread watchdog — a REPL or embedded use of start-node — nobody
would ever run stop-node, so this falls back to the historical behaviour of
running it on a throwaway thread. That is safe there precisely because nothing
is about to exit the process out from under it."
  (let* ((reason (or reason "shutdown requested"))
         (registered (null (sb-ext:cas (symbol-value '*shutdown-request*)
                                       nil (cons reason exit-code)))))
    (when registered
      (log-info "Shutdown requested: ~A (exit code ~D)" reason exit-code)
      ;; Wake the servicer the same way the signal handler does. This is not a
      ;; signal context, so the logging above is fine — but the SERVICING still
      ;; goes through one path, so a `stop` RPC and a SIGTERM tear the node down
      ;; identically instead of by two different mechanisms.
      (cond
        ((and *shutdown-servicer-thread*
              (bt:thread-alive-p *shutdown-servicer-thread*))
         (%write-shutdown-token))
        ((not *shutdown-watchdog-running*)
         ;; No servicer (a test, or an embedded caller that never installed the
         ;; handler) and no watchdog: nobody else would ever run stop-node.
         (bt:make-thread (lambda () (ignore-errors (stop-node)))
                         :name "node-shutdown"))))
    registered))

(defun node-shutdown-requested-p ()
  "The reason a shutdown was requested, or NIL (Core ShutdownRequested)."
  (car *shutdown-request*))

(defun %node-interrupt-requested-p ()
  "The node-wide stop predicate installed into bl:*interrupt-check*
(config.lisp), which states the contract. Two flags mean stop and this is the
only file that sees both: *shutdown-request* is set FIRST (the SIGTERM handler
just registers it), *ibd-stop-requested* later by stop-node."
  (or (bl.net:ibd-stop-requested-p)
      (node-shutdown-requested-p)))

(setf *interrupt-check* '%node-interrupt-requested-p)

(defun wait-for-shutdown-complete (&key (timeout 900))
  "Block until stop-node's *shutdown-complete* latch is set, or TIMEOUT
seconds pass. Returns T iff the shutdown completed. The default outlasts
stop-node's own 600s sync-thread join."
  (let ((deadline (+ (get-internal-real-time)
                     (* timeout internal-time-units-per-second))))
    (loop until *shutdown-complete*
          while (< (get-internal-real-time) deadline)
          do (sleep 0.05))
    (and *shutdown-complete* t)))

(defun %pending-shutdown-exit-code ()
  "The exit code the supervisor should see, or NIL while the node should keep
running. A node that stopped running without a request was not asked to stop
(fatal snapshot, dead sync thread) — that is the respawn case."
  (cond ((cdr *shutdown-request*))
        ((or (null *node*) (not (node-running *node*))) +node-exit-watchdog+)
        (t nil)))

(defun run-node-watchdog (&key (poll-seconds 1) (exit t))
  "Main-thread shutdown watchdog, the last form the supervisor launcher
evaluates (scripts/run-node.sh). Blocks until a shutdown is requested or the
node stops running, runs stop-node ON THIS THREAD — so the whole
flush/mempool.dat/peers.dat/banlist/wallet sequence completes before anything
exits — and then exits with a code the supervisor discriminates on:

  0  deliberate, completed stop (`stop` RPC, SIGTERM, -stopatheight): stay down
  1  deterministic failure (config, disk): back off, do not spin
  7  the node died unasked, or crashed: respawn

With EXIT NIL it returns the code instead of exiting (tests)."
  ;; SETF, not LET: the internal stop paths run on other threads and read the
  ;; GLOBAL value to decide whether anyone will run stop-node for them.
  (setf *shutdown-watchdog-running* t)
  (unwind-protect
       (loop
         (let ((code (%pending-shutdown-exit-code)))
           (when code
             (log-info "Shutdown watchdog: ~A — stopping node (exit code ~D)"
                       (or (node-shutdown-requested-p) "node is no longer running")
                       code)
             (ignore-errors (stop-node))
             (unless *shutdown-complete*
               (log-warn "Shutdown did not complete cleanly; exiting anyway"))
             ;; Release the servicer before exiting. It is a real thread blocked
             ;; in read(2), and SB-EXT:EXIT joins threads — a servicer that
             ;; never woke would hold the process for the full 5s timeout on
             ;; every shutdown. It always has a token when a request came
             ;; through request-node-shutdown or the signal handler, but NOT on
             ;; the exit-7 path (the node stopped running unasked, so nobody
             ;; ever asked), which is exactly the path that must not hang.
             (%write-shutdown-token)
             (if exit
                 (sb-ext:exit :code code :timeout 5)
                 (return code))))
         (sleep poll-seconds))
    (setf *shutdown-watchdog-running* nil)))

;;;; --- Assumeutxo P5: background-validation completion + promotion --------
;;;;
;;;; When the historical (validated-from-genesis) chainstate finishes
;;;; re-deriving history up to the snapshot base, its UTXO set must reproduce
;;;; the committed hash_serialized_3 exactly. maybe-validate-snapshot re-hashes
;;;; it and, on a match, promotes the snapshot chainstate to VALIDATED (Core
;;;; ChainstateManager::MaybeValidateSnapshot, validation.cpp:5986-6096); on a
;;;; mismatch it marks the snapshot INVALID, renames its dir aside for
;;;; forensics, and fires a fatal shutdown. A mid-run success keeps both
;;;; chainstates running until the next restart, when
;;;; validated-snapshot-cleanup swaps the LevelDB dirs so the snapshot
;;;; chainstate becomes the sole chainstate (Core ValidatedSnapshotCleanup,
;;;; validation.cpp:6299-6364). Assumeutxo status is never persisted, so it is
;;;; re-proven by re-hashing on every startup.

(defun %node-snapshot-chainstate (node)
  "The node's snapshot-derived chainstate (the one carrying a
from-snapshot-blockhash), regardless of its assumeutxo status, or NIL."
  (find-if #'bl.store:chain-state-from-snapshot-blockhash
           (node-chainstates node)))

(defun %default-snapshot-fatal (message)
  "Production reaction to a snapshot that failed background validation (Core
GetNotifications().fatalError): log the error and request node shutdown. The
invalid snapshot chainstate dir was already renamed aside for forensics; on
the next restart the node resumes normal IBD from the validated chain. Runs
on the sync thread, so it flips node-running (letting the loops wind
themselves down) and REQUESTS the shutdown rather than joining threads via
stop-node itself — the main thread runs the teardown, and the restart-worthy
exit code tells the supervisor to respawn."
  (log-error "[snapshot] !!! ~A" message)
  (log-error "[snapshot] the node will shut down and stop using any state built on the snapshot")
  (when *node*
    (setf (node-running *node*) nil)
    (request-node-shutdown "assumeutxo snapshot failed background validation"
                           :exit-code +node-exit-watchdog+)))

(defvar *snapshot-fatal-hook* '%default-snapshot-fatal
  "Funcalled with a message string when an assumeutxo snapshot fails
background validation mid-run. Production shuts the node down; tests rebind
it to record the fatal DECISION without exiting the image.")

(defun %snapshot-validation-preconditions-p (node historical snap)
  "T iff HISTORICAL is a validated-from-genesis chainstate that has reached
the snapshot base SNAP was built from — the point at which the snapshot can
be validated (Core MaybeValidateSnapshot's guard, validation.cpp:5990-6003).
A no-op-guarding predicate: false in every arrangement other than a
background sync that has just landed on its target."
  (and node snap historical
       (member historical (node-chainstates node))
       (bl.store:chain-state-from-snapshot-blockhash snap)
       (eq (bl.store:chain-state-assumeutxo-status snap) :unvalidated)
       (eq (bl.store:chain-state-assumeutxo-status historical) :validated)
       (bl.store:best-block-hash historical)
       (bl.store:chain-state-target-blockhash historical)
       (equalp (bl.store:chain-state-target-blockhash historical)
               (bl.store:chain-state-from-snapshot-blockhash snap))
       ;; ReachedTarget: the historical tip IS the target/base block.
       (equalp (bl.store:best-block-hash historical)
               (bl.store:chain-state-target-blockhash historical))))

(defun %mark-snapshot-invalid (node historical snap)
  "State mutation Core performs when a snapshot fails validation
(MaybeValidateSnapshot's handle_invalid_snapshot + InvalidateCoinsDBOnDisk,
validation.cpp:6026-6036): reset the historical chainstate's target back to
the network tip, mark the snapshot chainstate :invalid, close its coins DB and
rename its dir aside for forensics. No process shutdown here — the caller
drives that."
  (bl.store:set-chainstate-target historical nil)
  (setf (bl.store:chain-state-assumeutxo-status snap) :invalid)
  (bl.store:close-chainstate-coins-view snap)
  (ignore-errors
    (bl.store:rename-snapshot-chainstate-dir-invalid
     (node-data-directory node))))

(defun %validate-snapshot-against-commitment (node historical snap)
  "The core of Core's MaybeValidateSnapshot (validation.cpp:6039-6095), minus
the shutdown/cleanup reactions the callers own. Flush HISTORICAL, hash its
coins DB, and compare to the chainparams commitment for the snapshot base.

MATCH -> SNAP becomes :validated and HISTORICAL records its target-utxohash,
         so select-historical-chainstate stops returning it (the background
         work is done). Returns (values :success NIL).
MISMATCH / no chainparams entry -> %mark-snapshot-invalid, and returns
         (values :hash-mismatch MESSAGE) or (values :missing-chainparams MESSAGE)."
  ;; Core holds cs_main so the historical chainstate can't advance during
  ;; hashing; our caller runs on the single sync/startup thread, so it is
  ;; likewise frozen. Flush it first (Core ForceFlushStateToDisk) — this also
  ;; persists the historical's final tip so a crash right after validation
  ;; doesn't lose it.
  (%flush-chainstate historical)
  (let* ((base-hash (bl.store:chain-state-target-blockhash historical))
         (au (assumeutxo-data-for-blockhash (node-network node) base-hash)))
    (cond
      ((null au)
       (let ((msg (format nil "assumeutxo data not found for the snapshot base at height ~D — refusing to validate snapshot"
                          (bl.store:current-height historical))))
         (log-warn "[snapshot] ~A" msg)
         (%mark-snapshot-invalid node historical snap)
         (values :missing-chainparams msg)))
      (t
       (log-info "[snapshot] computing UTXO stats for the background chainstate to validate the snapshot — this may take a few minutes")
       (let ((got (bl.store:compute-utxo-set-hash
                   (bl.store:chain-state-coins-view historical)))
             (want (assumeutxo-data-hash-serialized au)))
         (cond
           ((equalp got want)
            (setf (bl.store:chain-state-assumeutxo-status snap) :validated
                  (bl.store:chain-state-target-utxohash historical) got)
            ;; VALIDATED lifts the snapshot chainstate's prune floor (Core: a
            ;; validated chainstate's GetPruneRange starts at 0 again); the
            ;; prune-walk cursor rewinds so the window the floor protected
            ;; becomes reclaimable.
            (bl.store:lift-prune-floor-on-promotion snap historical)
            ;; Core rebalances the caches immediately after promotion
            ;; (validation.cpp:6093): everything to the snapshot chainstate.
            (maybe-rebalance-caches node)
            (log-info "[snapshot] snapshot beginning at ~A has been fully validated"
                      (bl.crypto:bytes-to-hex
                       (bl.store:chain-state-from-snapshot-blockhash snap)))
            (values :success nil))
           (t
            (let ((msg (format nil "failed to validate the -assumeutxo snapshot state: hash mismatch (computed ~A, expected ~A)"
                               (bl.crypto:bytes-to-hex got)
                               (bl.crypto:bytes-to-hex want))))
              (log-error "[snapshot] ~A" msg)
              (%mark-snapshot-invalid node historical snap)
              (values :hash-mismatch msg)))))))))

(defun maybe-validate-snapshot (historical)
  "Connect-tip hook (Core MaybeValidateSnapshot at ConnectTip,
validation.cpp:3134-3135): when HISTORICAL — a background-validation
chainstate — reaches its snapshot base, re-hash its coins DB against the
chainparams commitment. On a match, the snapshot chainstate becomes the
node's validated chainstate (services regain NODE_NETWORK once no historical
chainstate remains, and getchainstates/validated-chainstate reflect it, all
via the select-* accessors) and the indexes rebind onto it (Core
init.cpp:1367-1383); the on-disk dir swap waits for the next restart. On a
mismatch the snapshot dir is renamed aside and the fatal hook is fired (Core
fatalError). Returns a SnapshotCompletionResult-style keyword; :skipped when
the preconditions aren't met (the common per-connect case), so it is safe to
call for any chainstate."
  (let* ((node *node*)
         (snap (and node (%node-snapshot-chainstate node))))
    (if (not (%snapshot-validation-preconditions-p node historical snap))
        :skipped
        (multiple-value-bind (result message)
            (%validate-snapshot-against-commitment node historical snap)
          (case result
            (:success
             (restart-indexes-for-validated-chainstate node)
             (log-info "[snapshot] promotion complete: the current chainstate (h=~D) is now fully validated; the background chainstate directories are consolidated on the next restart"
                       (bl.store:current-height
                        (node-current-chainstate node)))
             :success)
            (t
             (funcall *snapshot-fatal-hook* message)
             result))))))

(defun finalize-snapshot-validation-at-startup (node)
  "Startup completion + cleanup (Core LoadChainstate's MaybeValidateSnapshot +
ValidatedSnapshotCleanup, node/chainstate.cpp:196-235). If a persisted
historical chainstate has already reached the snapshot base (its background
sync completed on a previous run), re-prove the commitment hash: on success,
swap the LevelDB dirs so the snapshot chainstate becomes the sole
fully-validated chainstate (validated-snapshot-cleanup) — Core does this
shuffle on restart, not mid-run, because moving LevelDB dirs at runtime is
risky; on failure, abort startup (Core FAILURE_FATAL). Returns the result
keyword, or :skipped when there is nothing to finalize."
  (let ((historical (node-historical-chainstate node))
        (snap (%node-snapshot-chainstate node)))
    (if (not (%snapshot-validation-preconditions-p node historical snap))
        :skipped
        (multiple-value-bind (result message)
            (%validate-snapshot-against-commitment node historical snap)
          (case result
            (:success
             (validated-snapshot-cleanup node)
             :success)
            (t
             (error "Unable to complete -assumeutxo snapshot validation: ~A. ~
Restart to resume normal initial block download, or load a different snapshot."
                    message)))))))

(defun validated-snapshot-cleanup (node)
  "Startup-only LevelDB-dir consolidation after a snapshot was fully validated
on a previous run (Core ChainstateManager::ValidatedSnapshotCleanup,
validation.cpp:6299-6364): close every chainstate's coins DB, move the
snapshot chainstate's files into the default chainstate names (deleting the
now-unneeded background chainstate), and re-init the node with a single
fully-validated chainstate. Returns T when it swapped, NIL when there was
nothing to do."
  (let ((snap (%node-snapshot-chainstate node)))
    (unless (and snap (eq (bl.store:chain-state-assumeutxo-status snap)
                          :validated))
      (return-from validated-snapshot-cleanup nil))
    ;; ResetChainstates: release every coins DB handle before shuffling dirs.
    (dolist (cs (node-chainstates node))
      (bl.store:close-chainstate-coins-view cs))
    ;; Swap chainstate_snapshot/ into chainstate/ and delete the background one.
    (bl.store:promote-snapshot-chainstate-files (node-data-directory node))
    ;; Morph the snapshot chainstate struct into the sole primary chainstate:
    ;; drop its snapshot identity (default file names, no target/snapshot
    ;; marking) and reopen its coins view over the now-promoted chainstate/
    ;; LevelDB. Its shared block index and its (snapshot-tip) chain carry over
    ;; intact, so no block re-download is needed.
    (bl.store:clear-snapshot-chainstate-identity snap)
    (bl.store:open-chainstate-coins-view snap)
    (setf (node-chainstates node) (list snap))
    (log-info "[snapshot] background chainstate consolidated; running as a single fully-validated chainstate at height ~D"
              (bl.store:current-height snap))
    t))

;;; coinstatsindex rewind (Core BaseIndex::Rewind, index/base.cpp:239/290)
;;;
;;; coinstats records are keyed by HEIGHT with no block hash, there is no
;;; disconnect hook, and index writes reach the OS immediately while the
;;; chainstate tip only becomes durable at a flush (600s / N blocks / cache
;;; size — and a reorg does not trigger one). So a process kill inside that
;;; window leaves records holding an ABANDONED chain's state at heights at or
;;; below the tip that startup restores. The repair loop this replaces blessed
;;; any record it found at height <= tip and overwrote the stored meta hash,
;;; destroying the one piece of evidence that could have detected the
;;; divergence; every later query then served abandoned-chain numbers labelled
;;; with the active chain's hash. Core defends this with a per-record block
;;; hash it re-checks in RevertBlock; we recover the same guarantee at startup.

(defconstant +coinstatsindex-max-rewind+ 1000
  "How far back the coinstats rewind will verify records by recomputation
before giving up and rebuilding from genesis. Far deeper than any plausible
reorg; the cheap header-index walk is tried first and has no such bound.")

(defmethod bl.store:index-prepare-sync ((bfi bl.store:blockfilterindex) cs store)
  "BIP157 genesis-anchor migration, then repair a best marker left above the
tip (e.g. after invalidateblock): an index built before genesis indexing
existed seeded its header chain at the first STORED block, so every absolute
cfheaders/cfcheckpt/getblockfilter header it serves diverges from Core and
BIP157 light clients ban us. Detect and wipe it here; the backfill then
rebuilds from height 0 (the genesis filter is computed from chain
parameters). No-op on fresh and healthy indexes; on a pruned node a bad
index is kept (rebuild impossible) with a warning."
  (declare (ignore store))
  (let ((tip (bl.store:current-height cs)))
    (when (eq :rebuilt (bl.store:blockfilterindex-ensure-genesis-anchor bfi cs))
      (log-info "Block filter index wiped; rebuilding from genesis"))
    (when (> (bl.store:blockfilterindex-height bfi) tip)
      (log-warn "Block filter index best above tip (~D > ~D); repairing"
                (bl.store:blockfilterindex-height bfi) tip)
      (loop for h from tip downto 0
            for e = (bl.store:get-block-at-height cs h)
            when (and e (bl.store:blockfilterindex-has-block-p
                         bfi (bl.store:block-index-entry-hash e)))
              do (bl.store:blockfilterindex-set-best
                  bfi h (bl.store:block-index-entry-hash e))
                 (return)
            finally (bl.store:blockfilterindex-clear-best bfi)))))

(defmethod bl.store:index-prepare-sync ((csi bl.store:coinstatsindex) cs store)
  "Rewind a best marker that is not on the active chain (including one left
above the tip) before backfilling on top of it -- see %REWIND-COINSTATSINDEX."
  (%rewind-coinstatsindex csi cs store))

(defmethod bl.store:index-sync ((bfi bl.store:blockfilterindex) cs store &key undo-fn subsidy-fn progress)
  (declare (ignore subsidy-fn))
  (bl.store:build-blockfilterindex bfi cs store undo-fn :progress-callback progress))

(defmethod bl.store:index-sync ((csi bl.store:coinstatsindex) cs store &key undo-fn subsidy-fn progress)
  (bl.store:build-coinstatsindex csi cs store undo-fn subsidy-fn :progress-callback progress))

(defmethod bl.store:index-sync ((idx bl.store:txospender-index) cs store &key undo-fn subsidy-fn progress)
  "Walk forward from the best indexed height: the entries are keyed by
outpoint rather than by height, so they must be written in some order but
not necessarily this one; forward keeps the best marker meaningful if the
walk is interrupted. Stops, with a warning, at the first block whose body is
unavailable."
  (declare (ignore undo-fn subsidy-fn progress))
  (let* ((tip (bl.store:current-height cs))
         (from (1+ (bl.store:txospenderindex-height idx)))
         (done 0))
    (when (> from tip)
      (return-from bl.store:index-sync 0))
    (loop for h from from to tip
          for entry = (bl.store:get-block-at-height cs h)
          while entry
          do (when (bl:interrupt-requested-p)
               (log-warn "Spender index backfill stopped at height ~D" h)
               (return))
             (let* ((hash (bl.store:block-index-entry-hash entry))
                    (block (and store (bl.store:get-block store hash))))
               (cond
                 (block
                  (bl.store:txospenderindex-add-block idx block hash)
                  (bl.store:txospenderindex-set-best-block idx hash h)
                  (incf done))
                 (t
                  (log-warn "Spender index backfill stopped at height ~D: block body unavailable" h)
                  (return)))))
    done))

(defun catch-up-index (node index)
  "Catch INDEX up to NODE's validated chainstate tip (Core BaseIndex::Sync):
make its best marker trustworthy (INDEX-PREPARE-SYNC), then backfill the
shortfall (INDEX-SYNC), logging progress and the final height. Indexes bind
the validated chainstate (Core ValidatedChainstate) and index blocks in order
from genesis -- identical to the current chainstate while only the primary
exists, and the promoted snapshot chainstate after assumeutxo completion.
Shared by startup and the post-promotion index rebind. Synchronous, unlike
Core's background BaseIndex thread. Returns what INDEX-SYNC returned, or NIL
when there was nothing to do."
  (let* ((cs (node-validated-chainstate node))
         (tip (bl.store:current-height cs))
         (name (bl.store:index-name index)))
    (bl.store:index-prepare-sync index cs (node-block-store node))
    (when (< (bl.store:index-height index cs) tip)
      (log-info "Building ~A to height ~D..." name tip)
      (let ((n (bl.store:index-sync index cs (node-block-store node)
                                    :undo-fn #'bl.val:get-undo-data
                                    :subsidy-fn #'bl.val:calculate-block-subsidy
                                    :progress (lambda (h pct)
                                                (log-info "~A: height ~D (~,1F%)" name h pct)))))
        (log-info "~A build complete: ~D block~:P indexed" name n)
        (when (< (bl.store:index-height index cs) tip)
          (log-warn "~A stopped at height ~D of ~D (missing block/undo data ~
below the pruned horizon; the index needs genesis-contiguous history)"
                    name (bl.store:index-height index cs) tip))
        n))))

(defun restart-indexes-for-validated-chainstate (node)
  "Rebind every index onto the node's (now promoted) validated chainstate and
catch it up to its tip (Core restarts all indexes on background-sync
completion, init.cpp:1367-1383). During the background sync the indexes
tracked the historical chainstate up to the snapshot base; the promoted
chainstate carries the full chain past the base, so this resumes indexing
from where each index left off. A no-op when no index is enabled."
  (dolist (index (node-indexes node))
    (catch-up-index node index)))

(defun %coinstatsindex-fork-height (cs best-hash)
  "The height of the last block common to the active chain and the branch
BEST-HASH sits on (Core walks pprev in Rewind / FindForkInGlobalIndex). NIL
when the header index does not know BEST-HASH — headers are only persisted at
flush time, so the crash that produces a stale marker can also lose the branch
it names — or when the two chains do not actually meet."
  (let* ((stale (bl.store:get-block-index-entry cs best-hash))
         (tip (and stale (bl.store:get-block-index-entry
                          cs (bl.store:best-block-hash cs))))
         (fork (and tip (bl.val:find-fork-point stale tip))))
    ;; find-fork-point returns wherever its first walk stopped if the chains
    ;; never meet (a broken prev-entry link), so confirm the answer really is
    ;; on the active chain rather than trusting a fail-open result.
    (when (and fork (bl.store:entry-on-active-chain-p cs fork))
      (bl.store:block-index-entry-height fork))))

(defun %coinstatsindex-verified-height (csi cs store from)
  "The highest height at or below FROM whose stored record provably belongs to
the ACTIVE chain, found by recomputing it from its stored parent and the active
block at that height (see coinstatsindex-record-matches-block-p). This is the
fallback for when the header index cannot resolve the fork point, and it is
what keeps an ordinary unclean shutdown — index a few blocks ahead of the last
flushed tip, same chain — from costing a rebuild from genesis: the record at
the restored tip verifies on the first try. NIL if nothing verifies within
+coinstatsindex-max-rewind+."
  (loop for h from from downto (max 0 (- from +coinstatsindex-max-rewind+))
        do (when (zerop h)
             ;; Genesis is on every chain; its record is synthesized, not
             ;; folded from a parent, so presence is the whole check.
             (return (and (bl.store:coinstatsindex-get-stats csi 0) 0)))
           (let* ((entry (bl.store:get-block-at-height cs h))
                  (hash (and entry (bl.store:block-index-entry-hash entry)))
                  (block (and hash (bl.store:get-block store hash))))
             (when (and block
                        (bl.store:coinstatsindex-record-matches-block-p
                         csi block hash h
                         (bl.val:get-undo-data hash)
                         (bl.val:calculate-block-subsidy h)))
               (return h)))))

(defun %rewind-coinstatsindex (csi cs store)
  "Make the coinstats index's best marker name a block on the ACTIVE chain
before anything backfills on top of it, moving it back to the last common
ancestor when it does not (Core BaseIndex::Rewind). Records above the new best
are then rewritten by the backfill.

Returns NIL when the index was already consistent — the common case, and it
costs one hash comparison: a rewind that always rebuilt would be a severe
performance regression. Otherwise returns the height rewound to, or -1 when no
trustworthy record could be identified and the index must be rebuilt."
  (let ((tip (bl.store:current-height cs)))
    (multiple-value-bind (best-height best-hash)
        (bl.store:coinstatsindex-best csi)
      (when (minusp best-height)
        (return-from %rewind-coinstatsindex nil))
      (let ((active (and (<= best-height tip)
                         (bl.store:get-block-at-height cs best-height))))
        (when (and active best-hash
                   (equalp (bl.store:block-index-entry-hash active) best-hash))
          (return-from %rewind-coinstatsindex nil)))
      (log-warn "Coinstats index best (height ~D, ~A) is not on the active chain (tip ~D); rewinding"
                best-height
                (if best-hash (bl.crypto:bytes-to-hex best-hash) "no hash")
                tip)
      (let* ((fork (and best-hash (%coinstatsindex-fork-height cs best-hash)))
             (target (or (and fork
                              (<= fork tip)
                              (bl.store:coinstatsindex-get-stats csi fork)
                              fork)
                         (%coinstatsindex-verified-height csi cs store (min best-height tip))))
             (entry (and target (bl.store:get-block-at-height cs target))))
        (cond
          (entry
           (log-warn "Coinstats index rewound to height ~D (~A records above it will be rebuilt)"
                     target (- tip target))
           (bl.store:coinstatsindex-set-best
            csi target (bl.store:block-index-entry-hash entry))
           target)
          (t
           (log-warn "Coinstats index: no record below height ~D could be tied to the active chain; rebuilding from genesis"
                     (min best-height tip))
           (bl.store:coinstatsindex-clear-best csi)
           -1))))))

;;; -stopatheight / disk-space / periodic peers.dat dump support

(defvar *stop-at-height-triggered* nil
  "Once-only latch for -stopatheight so the shutdown request is made once.")

(defvar *disk-space-abort-triggered* nil
  "Once-only latch for the low-disk-space abort at flush points.")

(defvar *last-peers-dump-time* 0
  "Universal-time of the last periodic peers.dat dump.")

(defconstant +peers-dump-interval-seconds+ (* 15 60)
  "Cadence of the periodic peers.dat dump (Core DUMP_PEERS_INTERVAL = 15
minutes, net.cpp:63, scheduled at net.cpp:3560).")

(defun maybe-stop-at-height (height)
  "Request a node shutdown once HEIGHT reaches -stopatheight (Core
KernelNotifications::blockTip, node/kernel_notifications.cpp:61-66). Called
from connect-block on every ACTIVE-chainstate tip advance; a background
(targeted) chainstate never triggers it. Only REQUESTS the shutdown: the main
thread runs stop-node (which joins the sync thread — usually the caller here),
and the clean exit code stops the supervisor from respawning straight back
into the same trigger."
  ;; Under -debug=net, say WHICH guard declined when the height has been
  ;; reached. #478 wired this into the activation-step loop and a benchmark
  ;; reindex then ran straight past -stopatheight=134000 to 134898. The seam is
  ;; connected — ACTIVATION-STEPS-REPORT-THE-NEW-TIP-TO-STOPATHEIGHT proves
  ;; activate-best-chain calls this with the height it reached — so the refusal
  ;; is one of the guards below, and nothing on the outside can tell which.
  (when (and (plusp *stop-at-height*)
             (>= height *stop-at-height*)
             (or *stop-at-height-triggered*
                 (null *node*)
                 (not (node-running *node*))))
    (log-debug "stopatheight ~D reached at height ~D but not acted on: ~A"
               *stop-at-height* height
               (cond (*stop-at-height-triggered* "already triggered")
                     ((null *node*) "no *node*")
                     (t "node not running"))))
  (when (and (plusp *stop-at-height*)
             (>= height *stop-at-height*)
             (not *stop-at-height-triggered*)
             *node*
             (node-running *node*))
    (setf *stop-at-height-triggered* t)
    (log-info "Reached stopatheight=~D — requesting shutdown" *stop-at-height*)
    (request-node-shutdown (format nil "-stopatheight=~D reached" *stop-at-height*)
                           :exit-code +node-exit-clean+)
    t))

(defun check-disk-space (directory &optional (additional-bytes 0))
  "Free-space gate at flush points (Core CheckDiskSpace, util/fs_helpers.cpp:
87-93: available >= 50 MiB + ADDITIONAL-BYTES). Reads df -Pk; any failure to
determine free space passes — the gate must never false-positive a healthy
node into shutdown."
  (handler-case
      (let* ((out (with-output-to-string (s)
                    (uiop:run-program (list "df" "-Pk" (namestring directory))
                                      :output s :error-output nil)))
             (lines (remove-if (lambda (l) (zerop (length l)))
                               (uiop:split-string out :separator '(#\Newline))))
             (fields (and (>= (length lines) 2)
                          (remove-if (lambda (f) (zerop (length f)))
                                     (uiop:split-string (second lines)
                                                        :separator '(#\Space #\Tab)))))
             (avail-kb (and fields
                            (>= (length fields) 4)
                            (parse-integer (fourth fields) :junk-allowed t))))
        (or (null avail-kb)
            (>= (* avail-kb 1024) (+ 52428800 additional-bytes))))
    (error () t)))

(defvar *data-directory-lock-fd* nil
  "Open file descriptor holding the exclusive advisory lock on the data
directory's .lock file. Held for the lifetime of the process: closing it
releases the lock and lets a second node open the same directory.")

(defconstant +flock-ex-nb+ 6
  "flock(2) LOCK_EX (2) | LOCK_NB (4) — take an exclusive lock, or fail
immediately rather than waiting for the holder to exit.")

(defun lock-data-directory (directory)
  "Take Core's exclusive .lock on DIRECTORY (init.cpp:1158 -> util/fs_helpers.cpp:47).
Signals an error if another process already holds it.

Two nodes sharing a data directory destroy it: each keeps its own in-memory
block index and UTXO cache and flushes over the other's files, so the loser is
not the second to start but whichever flushes last. The coins LevelDB takes its
own lock, but only over that subdirectory and only once startup gets that far —
by which point this node has already read, and may already have rewritten,
chainstate.dat and headerindex.dat.

Advisory-only, like Core's: it stops a second bitcoin-lisp, not an unrelated
process editing the files."
  (let* ((path (merge-pathnames ".lock" directory))
         (fd (handler-case
                 (sb-posix:open (namestring path)
                                (logior sb-posix:o-creat sb-posix:o-rdwr)
                                #o644)
               (error (e)
                 (error "Cannot create the lock file at ~A: ~A" path e)))))
    (when (minusp (cffi:foreign-funcall "flock" :int fd :int +flock-ex-nb+ :int))
      (ignore-errors (sb-posix:close fd))
      ;; Core's wording exactly (init.cpp:1165): "Cannot obtain a lock on
      ;; directory %s. %s is probably already running." Not decoration —
      ;; feature_filelock.py matches on that sentence, and an operator whose
      ;; second node will not start searches for the string bitcoind prints.
      ;; Ours said "data directory" and joined the two halves with a semicolon.
      (let ((message (format nil "Cannot obtain a lock on directory ~A. ~A is probably already running."
                             directory
                             "bitcoin-lisp")))
        (log-error "~A" message)
        (error "~A" message)))
    ;; Keep the descriptor open. UNWIND from here on must not close it.
    (setf *data-directory-lock-fd* fd)))

(defun unlock-data-directory ()
  "Release the data-directory lock, if this process holds it. The .lock file
itself stays behind, as Core leaves it — its presence means nothing, only the
advisory lock on it does."
  (when *data-directory-lock-fd*
    (ignore-errors (sb-posix:close *data-directory-lock-fd*))
    (setf *data-directory-lock-fd* nil)))

(defvar *last-block-disk-check-time* 0
  "Universal time of the last block-write disk-space sample.")

(defvar *last-block-disk-check-ok* t
  "The verdict that sample produced.")

(defconstant +block-disk-check-interval-seconds+ 30
  "How often the block-write path re-samples free disk space.")

(defun check-disk-space-for-blocks (directory)
  "T when DIRECTORY has room for more block data, sampled at most every
+BLOCK-DISK-CHECK-INTERVAL-SECONDS+.

Core calls CheckDiskSpace before EVERY block and undo write (FindBlockPos /
FindUndoPos, blockstorage.cpp:337), which it can afford because its check is a
statvfs call. Ours shells out to `df`, so a per-block check would fork a
process per block during IBD. Sampling keeps the property that matters — a node
does not keep writing blocks onto a disk that is nearly full — with a bounded
lag of one interval.

Removing the caveat means binding statvfs(3) through CFFI, which is worth doing
and is not done here."
  (let ((now (get-universal-time)))
    (when (>= (- now *last-block-disk-check-time*)
              +block-disk-check-interval-seconds+)
      (setf *last-block-disk-check-time* now
            *last-block-disk-check-ok* (check-disk-space directory)))
    *last-block-disk-check-ok*))

(defun %gate-block-write-on-disk-space ()
  "Abort the node when the block directory has no room left, before a block
write rather than after (Core FindBlockPos -> CheckDiskSpace -> FatalError,
blockstorage.cpp:337). A no-op when there is no node or no data directory,
which is every test that connects blocks against a bare chainstate."
  (let ((dir (and *node* (node-data-directory *node*))))
    (when (and dir (not (check-disk-space-for-blocks dir)))
      (%abort-on-low-disk-space "Block write"))))

(defvar *flush-failure-abort-triggered* nil
  "Set once a flush failure has requested shutdown, so a failing flush called
again during teardown does not re-request it.")

(defun %abort-on-flush-failure (label condition)
  "Request shutdown after a flush failure (Core AbortNode from
FlushStateToDisk's catch, validation.cpp:2698). Exits non-clean: whatever made
the write fail — a full disk, a revoked mount, a corrupt database — will still
be there on respawn, so the supervisor should back off rather than spin."
  (unless *flush-failure-abort-triggered*
    (setf *flush-failure-abort-triggered* t)
    (request-node-shutdown (format nil "~A flush failed: ~A" label condition)
                           :exit-code +node-exit-error+)))

(defun %abort-on-low-disk-space (label)
  "Log + request shutdown once when free disk space is below the floor
(Core FlushStateToDisk's CheckDiskSpace failure -> FatalError \"Disk space
is too low!\", validation.cpp:2775/2808). Exits non-clean: respawning into a
full disk just reproduces the abort, so the supervisor backs off instead."
  (log-error "~A flush: Disk space is too low!" label)
  (unless *disk-space-abort-triggered*
    (setf *disk-space-abort-triggered* t)
    (request-node-shutdown "disk space is too low"
                           :exit-code +node-exit-error+)))

(defun maybe-dump-peer-addresses (node)
  "Dump the address book to peers.dat when the 15-minute cadence elapses
(Core scheduler DumpAddresses every DUMP_PEERS_INTERVAL, net.cpp:3560).
Called from the sync loop; also runs unconditionally at shutdown."
  (let ((now (get-universal-time)))
    (when (and (node-address-book node)
               (node-data-directory node)
               (>= (- now *last-peers-dump-time*) +peers-dump-interval-seconds+))
      (setf *last-peers-dump-time* now)
      (handler-case
          (progn
            (bl.net:save-address-book
             (node-address-book node)
             (bl.net:peers-dat-path (node-data-directory node)))
            (log-debug "Periodic peers.dat dump (~D entries)"
                       (bl.net:address-book-count
                        (node-address-book node))))
        (error (e)
          (log-warn "Periodic peers.dat dump failed: ~A" e)))
      t)))

(defun %ensure-genesis-index-entry (network)
  "Put NETWORK's genesis into the block index, with a correct header (the
difficulty walk-back on testnet needs it).

Must run BEFORE -reindex. REINDEX-BLOCK-INDEX links each record to a parent
already in the index and parks the rest, so the index needs a ROOT or the drain
never starts: on a datadir with no existing index every record parks and
nothing is ever added. That is exactly what happened against a real Core
testnet4 datadir — 134,923 records read, 134,923 orphaned, 0 linked — and it
went unnoticed because reindexing a datadir that ALREADY has an index (the only
case ever exercised) has genesis for a root."
  (let* ((genesis-hash (bl.store:network-genesis-hash network))
         (genesis-entry (bl.store:get-block-index-entry
                         (node-chain-state *node*) genesis-hash))
         (genesis-header (make-genesis-header network)))
    (if genesis-entry
        ;; Fix existing entry if it has a missing or zeroed header, or a
        ;; persisted header with the wrong merkle root (the old shared-constant
        ;; make-genesis-header gave testnet4 mainnet's merkle root, and header
        ;; indexes saved before the fix still carry it).
        (let ((h (bl.store:block-index-entry-header genesis-entry)))
          (when (or (null h)
                    (zerop (bl.ser:block-header-bits h))
                    (not (equalp (bl.ser:block-header-merkle-root h)
                                 (bl.ser:block-header-merkle-root
                                  genesis-header))))
            (setf (bl.store:block-index-entry-header genesis-entry)
                  genesis-header)
            ;; This REPLACES a header object on an entry that already exists,
            ;; the one mutation the packed change-detector behind the header
            ;; index delta log cannot see (it tracks presence, not identity).
            ;; Force a full snapshot so the corrected genesis actually lands.
            (bl.store:save-header-index
             (node-chain-state *node*) :force-full t)))
        ;; Create new genesis entry
        (bl.store:add-block-index-entry
         (node-chain-state *node*)
         (bl.store:make-block-index-entry
          :hash genesis-hash
          :height 0
          :header genesis-header
          :prev-entry nil
          :chain-work 0
          :status :valid
          :tx-count 1)))))   ; genesis carries exactly its coinbase

(defun %start-indexes (txindex blockfilterindex txospenderindex coinstatsindex
                       reindex-chainstate)
  "Open every enabled index on *NODE* and catch it up to the tip (Core
init.cpp \"Step 8: start indexers\" -- our catch-ups are synchronous, see
CATCH-UP-INDEX). Prune locks are re-registered from scratch."
  ;; Transaction index. The catch-up is what makes enabling -txindex on a
  ;; synced node index history (build-tx-index had no caller until #356);
  ;; it resumes from the best-block marker, so a current index costs one
  ;; marker lookup (ga9-txindex-startup-catch-up-is-wired pins the call).
  (when txindex
    (log-info "Initializing transaction index...")
    (setf (node-tx-index *node*)
          (bl.store:init-tx-index (node-data-directory *node*) :enabled t))
    (bl.rpc:set-rpc-warmup-status "Catching up transaction index...")
    (catch-up-index *node* (node-tx-index *node*))
    (log-info "Transaction index loaded: ~D entries"
              (bl.store:txindex-count (node-tx-index *node*))))
  ;; Prune locks are re-registered from scratch on every start: registration is
  ;; by name, so a re-init replaces rather than accumulates, but an index that
  ;; was enabled last run and is disabled this one would otherwise leave a lock
  ;; behind holding the prune horizon down forever.
  (bl.store:clear-prune-locks)
  ;; Likewise the once-per-run stall latch of the connect-time index hook.
  (setf *index-stall-logged* '())

  ;; Initialize BIP158 block filter index (optional)
  (when blockfilterindex
    (log-info "Initializing block filter index...")
    (setf (node-blockfilterindex *node*)
          (bl.store:init-blockfilterindex (node-data-directory *node*)
                                                       :enabled t))
    (log-info "Block filter index loaded: indexed to height ~D"
              (bl.store:blockfilterindex-height (node-blockfilterindex *node*)))
    ;; The filter index needs each block's undo data to build its filter, so
    ;; pruning must not run ahead of it (Core blockfilterindex AllowPrune() ->
    ;; true, and BaseIndex::SetBestBlockIndex takes a lock at its best height).
    (let ((bfi (node-blockfilterindex *node*)))
      (bl.store:register-prune-lock
       "blockfilterindex"
       (lambda ()
         ;; -1 is "nothing indexed yet", which is Core's height_first ==
         ;; INT_MAX: no height to protect, so no constraint. Returning it
         ;; verbatim would drive the ceiling to 1 and stop pruning outright.
         (let ((h (bl.store:blockfilterindex-height bfi)))
           (and (plusp h) h)))))
    ;; One-time catch-up over already-stored blocks, before the sync thread
    ;; starts (single-threaded here, so no writer races). Fresh-from-genesis
    ;; nodes have nothing to do; the connect-time hook then indexes forward.
    (bl.rpc:set-rpc-warmup-status "Catching up block filter index...")
    (catch-up-index *node* (node-blockfilterindex *node*)))

  ;; Initialize txospenderindex (optional). Core starts every index's
  ;; background sync from init, so enabling -txospenderindex on a synced node
  ;; indexes history; until P2e-1 this index was only ever caught up on
  ;; assumeutxo promotion, and the flag indexed nothing historical (the same
  ;; no-caller shape as ga9-txindex-startup-catch-up-is-wired).
  (when txospenderindex
    (log-info "Initializing spender index...")
    (setf (node-txospenderindex *node*)
          (bl.store:init-txospender-index (node-data-directory *node*)
                                                      :enabled t))
    (let ((best (bl.store:txospenderindex-best-block
                 (node-txospenderindex *node*))))
      (log-info "Spender index loaded: best block ~A"
                (if best (bl.crypto:bytes-to-hex best) "none")))
    (bl.rpc:set-rpc-warmup-status "Catching up txospender index...")
    (catch-up-index *node* (node-txospenderindex *node*)))

  ;; Initialize coinstatsindex (optional). Like the filter index, catch up over
  ;; already-stored blocks before the sync thread starts, then the connect-time
  ;; hook advances it. Its running MuHash must be contiguous from genesis, so a
  ;; pruned node (missing early undo data) can only build it if its stored
  ;; history reaches genesis -- otherwise the backfill stops at the first gap.
  (when coinstatsindex
    (log-info "Initializing coinstats index...")
    (setf (node-coinstatsindex *node*)
          (bl.store:init-coinstatsindex (node-data-directory *node*)
                                                    :enabled t))
    (log-info "Coinstats index loaded: indexed to height ~D"
              (bl.store:coinstatsindex-height (node-coinstatsindex *node*)))
    ;; Same reasoning as the filter index (Core coinstatsindex AllowPrune() ->
    ;; true): its per-block statistics are derived from undo data.
    (let ((csi (node-coinstatsindex *node*)))
      (bl.store:register-prune-lock
       "coinstatsindex"
       (lambda ()
         (let ((h (bl.store:coinstatsindex-height csi)))
           (and (plusp h) h)))))
    ;; A chainstate reindex may have changed UTXO-set contents (e.g. dropping
    ;; unspendable outputs), so the coinstats records must be rebuilt to stay
    ;; consistent. Clear the best marker to force a full rebuild below.
    (when reindex-chainstate
      (bl.store:coinstatsindex-clear-best (node-coinstatsindex *node*))
      (log-info "Coinstats index: rebuilding after chainstate reindex"))
    (bl.rpc:set-rpc-warmup-status "Catching up coinstats index...")
    (catch-up-index *node* (node-coinstatsindex *node*))))

(defun start-node (&key (data-directory "~/.bitcoin-lisp/")
                        (network :testnet3)
                        (log-level :info)
                        (log-file nil)
                        (log-rate-limit t)
                        (flat-block-files bl.store:*flat-block-files*)
                        (reindex nil)
                        (console-log t)
                        (max-peers 8)
                        (max-connections 125)
                        (accept-stale-fee-estimates nil)
                        (sync t)
                        (txindex nil)
                        (blockfilterindex nil)
                        (prune nil)
                        (rpc-port nil)
                        (rpc-bind "127.0.0.1" rpc-bind-supplied-p)
                        (rpc-user nil)
                        (rpc-password nil)
                        (rpc-auth nil)
                        (rpc-allow-ip nil)
                        (listen t)
                        (listen-bind "0.0.0.0")
                        (listen-onion t)
                        (tor-control nil)
                        (tor-password nil)
                        (dbcache-mib nil)
                        (mocktime nil)
                        (pid-file nil)
                        (connect-nodes nil connect-nodes-supplied-p)
                        (seednode nil)
                        (load-block nil)
                        (asmap nil)
                        (migrate-datadir nil)
                        (whitelist nil)
                        (whitebind nil)
                        (block-notify nil)
                        (startup-notify nil)
                        (shutdown-notify nil)
                        (debug-categories nil)
                        (debug-exclude nil)
                        (log-time-micros nil)
                        (log-thread-names nil)
                        (test-activation-heights nil)
                        (v2transport nil)
                        (coinstatsindex nil)
                        (txospenderindex nil)
                        (reindex-chainstate nil)
                        (force-compact-db nil)
                        (peer-block-filters nil)
                        (tx-reconciliation nil)
                        (webui nil webui-supplied-p)
                        (webui-path nil)
                        (webui-open nil)
                        (wallet nil wallet-supplied-p)
                        (wallet-names nil)
                        (log-level-specs nil)
                        (port nil)
                        (network-active t)
                        ((:rest rest-enabled) nil)
                        (addnode nil)
                        (blocksonly nil))
  "Start the Bitcoin node.

DATA-DIRECTORY: Path to store blockchain data (mainnet uses mainnet/ subdirectory)
NETWORK: :testnet3 or :mainnet
LOG-LEVEL: :debug, :info, :warn, or :error
LOG-FILE: If non-nil, also append node logs to this path (in addition to console)
CONSOLE-LOG: If T (default), mirror logs to *standard-output* / REPL
MAX-PEERS: outbound full-relay connections (Core's 8)
MAX-CONNECTIONS: Core -maxconnections, the automatic connection total (default
  125); inbound capacity is what remains after MAX-PEERS, the block-relay-only
  and the feeler slots
SYNC: If T, start syncing immediately
TXINDEX: If T, enable transaction index for getrawtransaction lookups
BLOCKFILTERINDEX: If T, enable the BIP158 basic block filter index (getblockfilter,
  scanblocks, getdescriptoractivity)
PRUNE: Block pruning target in MiB (nil=off, 1=manual-only, >=550=automatic)
RPC-PORT: Port for RPC server (nil = no RPC, default 18332 testnet / 8332 mainnet)
RPC-BIND: Address to bind RPC server (default 127.0.0.1)
RPC-USER: RPC authentication username (nil = no auth)
RPC-PASSWORD: RPC authentication password
RPC-AUTH: list of -rpcauth specs (USERNAME:SALT$HMAC), extra credentials
  accepted alongside the RPC-USER/RPC-PASSWORD or .cookie pair
RPC-ALLOW-IP: list of -rpcallowip specs allowed to reach the RPC port;
  loopback is always allowed, and a non-loopback RPC-BIND is honoured only
  when this is non-empty
LISTEN-ONION: If T (default, like Core -listenonion) and LISTEN is on,
  connect to the local Tor control port, create a v3 onion service forwarding
  to a loopback listener on port+1, and advertise the .onion address
LISTEN-ONION requires a reachable Tor daemon to do anything; without one the
  torcontrol thread just retries with backoff
TOR-CONTROL: Tor control host:port (nil = 127.0.0.1:9051, Core -torcontrol)
TOR-PASSWORD: Tor control port password (Core -torpassword)
WEBUI: Serve the web UI at /ui/ on the RPC port (docs/gui-plan.md P0).
  Default: on for every network except mainnet (operator's choice there)
WEBUI-PATH: Web UI asset directory (nil = the repo's ui/ directory)
WEBUI-OPEN: If T (default nil), open http://localhost:<rpcport>/ui/ in the
  local browser after the RPC server starts — the local-daemon pattern
WALLET: Enable descriptor-wallet support (createwallet/loadwallet/... RPCs,
  per-wallet storage under <datadir>/wallets/). Default: on for every network
  except mainnet, where holding keys is the operator's explicit opt-in
  (docs/wallet-plan.md §1 deployment posture)
PORT: P2P LISTEN port override (Core -port); the onion target moves to PORT+1.
  NIL = the network default. Dialing peers keeps the chain default port.
NETWORK-ACTIVE: If NIL, start with all P2P activity disabled (Core
  -networkactive=0); re-enable at runtime with setnetworkactive.
REST: If T, serve the Core-style REST interface under /rest/ on the RPC port
  (Core -rest; default OFF, DEFAULT_REST_ENABLE = false, init.cpp:153).
ADDNODE: List of \"host[:port]\" strings to keep connected as manually-added
  peers (Core -addnode as a config option; same list addnode RPC manages).
BLOCKSONLY: If T, reject transactions from network peers (Core -blocksonly,
  default false): fRelay=0 in our version messages, tx announcements/txs
  from peers disconnect them, no feefilter. Local submissions still relay;
  block relay is unaffected.

Returns the node instance."
  (when *node*
    (log-warn "Node already running, stopping first")
    (stop-node))

  ;; A NEW datadir gets a wallets/ subdirectory, whether or not the wallet is
  ;; enabled (Core common/init.cpp:45-63, base path and network path both). Core
  ;; makes it only at creation time, so an existing datadir's layout is never
  ;; changed underneath its owner, and wallet code then USES the subdirectory
  ;; only if it is already there.
  ;;
  ;; FIRST, before anything else in this function: the very next thing that
  ;; happens is the log file being opened, and ENSURE-DIRECTORIES-EXIST on
  ;; <datadir>/<network>/debug.log CREATES the network directory. Run after
  ;; that, the "did this exist?" test is answered by our own side effect and is
  ;; always false.
  ;;
  ;; Small, and it was blocking the whole functional-test corpus: the framework
  ;; builds a shared 199-block cache datadir once and copies it per test, and
  ;; its cleanup does `os.rmdir(cache/regtest/wallets)`. With no such directory
  ;; that raises, the cache build FAILS, and every run then falls back on
  ;; whatever cache was last built successfully — which here was one written in
  ;; the pre-Core per-block format, months old. Every non-clean-chain test in
  ;; the suite was running against it.
  (%ensure-wallets-subdirectory data-directory network)

  ;; Real time, not the mockable clock: uptime must keep measuring real elapsed
  ;; seconds while a functional test drives setmocktime, exactly as Core's
  ;; GetUptime uses SteadyClock rather than GetTime (common/system.cpp:134).
  (setf *node-start-time* (bl.ser:get-real-unix-time))

  ;; Wire up logging BEFORE init-node so its log-info calls go somewhere.
  ;; Without these, the node runs silently — the May 5 restart had this
  ;; failure mode (no node.log entries since May 2 16:32 crash).
  (when console-log
    (enable-console-logging))
  ;; A node logs to <datadir>/debug.log unless told otherwise, as Core does
  ;; (DEFAULT_DEBUGLOGFILE, "debug.log" under the datadir; -debuglogfile=0
  ;; disables it). Before this the node wrote no file at all without an
  ;; explicit -logfile, which is also what Core's functional framework reads
  ;; for EVERY node it starts, and what an operator looks for first.
  (let ((path (%resolve-log-file log-file data-directory network)))
    (when path
      ;; The network directory may not exist yet — the block store creates it
      ;; later — and the first log line is emitted before that.
      ;;
      ;; A path we cannot open is a fatal init error, with Core's wording
      ;; (init/common.cpp:116-119). `-debuglogfile=foo/foo.log` names a
      ;; subdirectory Core does NOT create, and it refuses to start rather than
      ;; run a node whose operator believes it is logging somewhere it is not.
      ;; ENSURE-DIRECTORIES-EXIST alone would have created `foo/` and started
      ;; happily, which is the opposite of what the option means.
      (unless (probe-file (make-pathname :name nil :type nil :defaults path))
        (error "Could not open debug log file ~A" (namestring path)))
      (ensure-directories-exist path)
      (handler-case (start-file-logging path)
        (error ()
          (error "Could not open debug log file ~A" (namestring path))))))
  ;; The level BEFORE the flush below, not 270 lines further down where it used
  ;; to be set: a deferred line is filtered when it is emitted, so flushing
  ;; first would judge every queued line against whatever level the image
  ;; happened to hold — the load-time default in a fresh process, and in a REPL
  ;; or test image whatever the PREVIOUS start-node left behind.
  (setf *current-log-level* log-level)
  ;; Per-category thresholds from -loglevel=<category>:<level>. Cleared first,
  ;; so a restart in the same image does not inherit the previous node's.
  (clear-category-log-levels)
  (dolist (spec log-level-specs)
    (multiple-value-bind (category level) (parse-loglevel-spec spec)
      (when category (set-category-log-level category level))))
  ;; Everything config parsing queued before the file existed. Core logs its
  ;; args after InitLogging for the same reason (init.cpp), and its functional
  ;; tests read those lines back out of debug.log.
  (flush-deferred-log-lines)

  ;; Operator hooks (Core -blocknotify / -shutdownnotify). Set before anything
  ;; can fire them.
  (setf *block-notify-command* block-notify
        *shutdown-notify-commands* shutdown-notify)

  ;; -pid: written once the log exists, so a failure is on the record, and
  ;; before any long-running startup work, so a supervisor watching for the
  ;; file does not have to wait out a reindex to learn our PID.
  (let ((path (write-pid-file pid-file data-directory)))
    (when path (log-info "PID file: ~A" path)))

  ;; -debug=<category> / -debugexclude=<category> (Core init/common.cpp).
  ;; Applied before init-node so startup's own category lines are subject to
  ;; them. An unknown name signals rather than being ignored: a silently
  ;; dropped -debug=nett is an operator staring at a log that will never
  ;; contain what they asked for.
  (setf *log-time-micros* (and log-time-micros t)
        *log-thread-names* (and log-thread-names t))
  (let ((enabled (apply-log-categories debug-categories debug-exclude)))
    (when enabled
      (log-info "Debug logging categories: ~{~A~^ ~}" enabled)))

  ;; -testactivationheight=name@height moves a buried deployment so a regtest
  ;; chain can be driven across it in a handful of blocks (Core
  ;; chainparams.cpp:49-67). Applied before anything validates a block. A
  ;; malformed entry signals, as Core raises: a typo'd deployment name that was
  ;; silently ignored would leave the test running against the very height it
  ;; was trying to move.
  (bl.val:apply-test-activation-heights test-activation-heights)
  (when test-activation-heights
    (unless (eq network :regtest)
      (error "-testactivationheight is for regression testing (-regtest mode) only"))
    (log-warn "Activation heights overridden by -testactivationheight: ~{~A~^ ~}"
              test-activation-heights))

  ;; -mocktime: the startup form of setmocktime, for tests that need a fixed
  ;; clock before the first RPC can be made. Same regtest gate the RPC has.
  (when mocktime
    (unless (eq network :regtest)
      (error "-mocktime is for regression testing (-regtest mode) only"))
    (unless (and (integerp mocktime) (<= 0 mocktime))
      (error "Invalid -mocktime: ~A. Must be a non-negative integer." mocktime))
    (setf bl.ser:*mock-time*
          (if (zerop mocktime) nil mocktime))
    (log-info "Mock time set to ~D" mocktime))

  ;; -dbcache, split across the coins cache AND every database's block cache
  ;; the way Core splits it (CalculateCacheSizes, node/caches.cpp:57-72, then
  ;; kernel::CacheSizes). We used to spend the whole budget on the in-memory
  ;; coins cache and give the LevelDBs nothing, so -dbcache=4000 bought a large
  ;; cache sitting on top of databases still reading a block per level for
  ;; every miss. Computed BEFORE init-node, which is what opens them.
  (when dbcache-mib
    (unless (and (integerp dbcache-mib) (>= dbcache-mib 4))
      (error "Invalid dbcache-mib: ~A. Must be an integer >= 4." dbcache-mib)))
  (let* ((total (if dbcache-mib
                    (* dbcache-mib 1024 1024)
                    bl.store::+default-db-cache-bytes+))
         (sizes (bl.store:calculate-cache-sizes
                 total
                 :tx-index txindex
                 ;; The filter and coinstats indexes share one per-index share,
                 ;; as Core divides its filter budget by n_indexes.
                 :filter-index-count (+ (if blockfilterindex 1 0)
                                        (if coinstatsindex 1 0)))))
    (setf bl.store::*cache-sizes* sizes
          *coins-cache-budget-bytes*
          (bl.store:cache-sizes-coins sizes))
    (log-info "Cache budget ~D MiB: coins ~D MiB, coins-db ~D MiB, ~
txindex ~D MiB, per-index ~D MiB"
              (floor total 1048576)
              (floor (bl.store:cache-sizes-coins sizes) 1048576)
              (floor (bl.store:cache-sizes-coins-db sizes) 1048576)
              (floor (bl.store:cache-sizes-tx-index sizes) 1048576)
              (floor (bl.store:cache-sizes-filter-index sizes) 1048576)))

  ;; Validate the pruning configuration BEFORE assigning the global — a
  ;; config-validation error must not leave *prune-target-mib* set (a failed
  ;; start-node previously leaked the half-applied prune setting into the
  ;; process, making e.g. a later loadtxoutset believe the node is pruned).
  (when prune
    (unless (or (= prune 1) (>= prune 550))
      (error "Invalid prune target: ~A MiB. Must be 1 (manual-only) or >= 550." prune))
    (when (and prune txindex)
      (error "Cannot enable both pruning and txindex. Pruned blocks cannot be looked up."))
    ;; Core refuses the same pair for the spender index, and for the same
    ;; reason: answering a lookup means READING the spending transaction back
    ;; from its block, which a pruned node no longer has (init.cpp, the
    ;; -txospenderindex prune check).
    (when (and prune txospenderindex)
      (error "Cannot enable both pruning and txospenderindex. Pruned blocks cannot be looked up."))
    ;; Bitcoin Core init.cpp: -prune is incompatible with -reindex-chainstate --
    ;; the wipe leaves the UTXO set to be replayed from stored blocks, but early
    ;; blocks are pruned, so a pruned reindex-chainstate wedges at the first gap.
    (when (and peer-block-filters (not blockfilterindex))
      (error "Cannot set -peerblockfilters without -blockfilterindex."))
    (when (and prune reindex-chainstate)
      (error "Prune mode is incompatible with -reindex-chainstate (pruned blocks cannot be replayed). Use a full resync instead.")))
  (setf *prune-target-mib* prune)

  ;; -port: validate, then make it the single global listen-port override.
  ;; Always assigned (NIL clears), so a fresh start-node never inherits a
  ;; stale override from a previous run.
  (when port
    (unless (and (integerp port) (<= 1 port 65535))
      (error "Invalid port specified in -port: '~A'" port)))
  (setf *p2p-port-override* port)

  ;; -externalip: validate resolvability up front (Core init errors before
  ;; the network starts, init.cpp:1806 ResolveErrMsg); the AddLocal itself
  ;; happens after the tor block below, whose clear-local-addresses would
  ;; otherwise wipe it.
  (dolist (spec bl.net:*external-ips*)
    (unless (bl.net:parse-network-address spec)
      (error "Cannot resolve -externalip address: '~A'" spec)))

  ;; Initialize node
  ;; Datadir layout (Core doc/files.md). BOTH of these must run BEFORE
  ;; init-node, which opens the databases: nothing below coordinates with an
  ;; open LevelDB handle, and moving a directory out from under one is how a
  ;; datadir gets corrupted rather than migrated.
  ;; The per-NETWORK directory, not the base one. Core's layout lives under
  ;; testnet4/ (or the network's own subdirectory), so pointing either of these
  ;; at the base made both of them inspect a directory that holds nothing but
  ;; that subdirectory — the report saw a Core-shaped layout and said nothing,
  ;; and the migration would have moved nothing. Found by starting a real node
  ;; on a legacy testnet4 datadir and watching it log the legacy undo path with
  ;; no warning; the unit tests missed it because their temp datadir has no
  ;; network subdirectory, so base and network directory are the same path.
  (let ((network-dir (network-data-path
                      (uiop:ensure-directory-pathname data-directory) network)))
  (when migrate-datadir
    (let ((moves (bl.store:migrate-datadir-layout network-dir)))
      (if moves
          (dolist (m moves)
            (log-info "Migrated ~A: ~A -> ~A" (first m) (second m) (third m)))
          (log-info "-migratedatadir: nothing to move; the layout is already Core's"))))
  ;; Datadir layout: report anything still resolving to the pre-Core location.
  ;; Reported rather than silently tolerated — an operator whose node cannot be
  ;; driven by Core's functional tests should be told WHICH directory is the
  ;; reason, and `-migratedatadir` is the fix.
  (let ((legacy (bl.store:datadir-layout-report network-dir)))
    (when legacy
      (log-warn "Data directory uses the pre-Core layout for: ~{~A~^, ~}. ~
Core's functional tests address these paths by name. Run with -migratedatadir ~
to move them (the node must be stopped)."
                (mapcar #'first legacy))
      (dolist (entry legacy)
        (log-info "  ~A: using ~A (Core: ~A)"
                  (first entry) (third entry) (second entry))))))


  (setf *node* (init-node data-directory :network network :log-level log-level))
  (setf (node-max-peers *node*) max-peers)
  ;; Core -maxconnections is the automatic TOTAL (net.h:81); MAX-PEERS stays
  ;; the outbound full-relay count and the remainder is inbound capacity.
  (setf *max-inbound-connections* (automatic-inbound-capacity max-connections max-peers))
  ;; Core -acceptstalefeeestimates is regtest-only (init.cpp:1654-1656).
  (when accept-stale-fee-estimates
    (unless (eq network :regtest)
      (error "acceptstalefeeestimates is not supported on ~A chain."
             (string-downcase (symbol-name network))))
    (setf bl.mp:*accept-stale-fee-estimates* t))
  ;; -blocksonly: reject transactions from network peers (Core
  ;; ignore_incoming_txs). Always assigned so a fresh start-node never
  ;; inherits a stale value from a previous run.
  (setf *blocksonly* (and blocksonly t))
  (when *blocksonly*
    (log-info "Blocksonly mode: transactions from network peers are rejected (-blocksonly)"))
  ;; -networkactive=0: start with all P2P activity disabled (Core passes the
  ;; flag to the CConnman ctor, init.cpp:1648); setnetworkactive re-enables.
  (setf (node-network-active *node*) (and network-active t))
  (unless (node-network-active *node*)
    (log-warn "P2P network activity DISABLED (-networkactive=0)"))
  ;; -addnode: seed the manually-added peer list the addnode RPC manages
  ;; (Core m_added_node_params from GetArgs(\"-addnode\"), init.cpp:2107).
  (when addnode
    (setf (node-added-nodes *node*) (copy-list addnode))
    (log-info "Manually-added peers (-addnode): ~{~A~^, ~}" addnode))
  ;; -connect: dial ONLY these, and stop choosing peers from the address book
  ;; (Core init.cpp:2214-2225). The single value "0" — which is also what
  ;; -noconnect parses to — means no outbound connections at all; Core tests
  ;; for exactly that shape, so -connect=0 -connect=1.2.3.4 leaves BOTH as
  ;; targets rather than being read as a disable.
  ;; -asmap: bucket peers by ASN instead of /16. Loaded before any peer can
  ;; connect, and FATAL on failure as Core's is (init.cpp:1587-1600) — a node
  ;; that silently kept /16 bucketing after being told to use an ASN map would
  ;; have exactly the eclipse exposure the operator was closing.
  (setf bl.net::*asmap* nil)
  (when (and asmap (stringp asmap) (plusp (length asmap))
             (not (string= asmap "0")))
    (let ((path (if (uiop:absolute-pathname-p asmap)
                    asmap
                    (merge-pathnames asmap (uiop:ensure-directory-pathname
                                            (or data-directory "./"))))))
      (bl.net:load-asmap-file path)
      (log-info "Using asmap version ~A for IP bucketing"
                (bl.net:asmap-version))))
  ;; ⚠️ Core logs BOTH branches (init.cpp:1628,1631) — the /16 case is not a
  ;; silent default there, and feature_asmap.py greps for it to tell a node
  ;; that fell back apart from one that never had a map. We logged only the
  ;; success side, so the interesting case said nothing.
  (unless bl.net::*asmap*
    (log-info "Using /16 prefix for IP bucketing"))
  ;; -whitelist / -whitebind: permission grants by address range. Applied
  ;; before any peer can connect. A malformed spec is fatal, as Core's is
  ;; (init.cpp fails on the first entry NetWhitelistPermissions::TryParse
  ;; rejects): a typo'd range grants nothing and the operator never finds out.
  (setf bl.net::*whitelist-entries* '()
        bl.net::*whitebind-flags* 0)
  (dolist (spec whitelist)
    (let ((entry (bl.net:parse-whitelist-entry spec)))
      (unless entry
        (error "Invalid netmask, IP address or permission in -whitelist: '~A'" spec))
      (setf bl.net::*whitelist-entries*
            (append bl.net::*whitelist-entries* (list entry)))))
  (dolist (spec whitebind)
    ;; -whitebind is "perms@addr:port": the ADDRESS half is a bind target, not
    ;; a range, and we bind one listener, so only the PERMISSIONS are kept.
    ;; Core refuses "out" here — a listening socket has no outgoing peers.
    (multiple-value-bind (flags direction rest)
        (bl.net:parse-permission-flags spec)
      (declare (ignore rest))
      (unless flags
        (error "Invalid permission in -whitebind: '~A'" spec))
      (when (member direction '(:out))
        (error "whitebind may only be used for incoming connections (\"out\" was passed)"))
      (setf bl.net::*whitebind-flags*
            (logior bl.net::*whitebind-flags* flags))))
  (when (or whitelist whitebind)
    (log-info "Net permissions configured: ~D -whitelist range(s), -whitebind ~A"
              (length whitelist)
              (or (bl.net:permission-flag-names
                   bl.net::*whitebind-flags*)
                  "none")))
  (setf *use-addrman-outgoing* t *connect-nodes* '() *seed-nodes* '())
  ;; -seednode: address sources, not peers (Core connOptions.vSeedNodes).
  (when seednode
    (setf *seed-nodes* (copy-list seednode))
    (log-info "Address seed nodes (-seednode): ~{~A~^, ~}" seednode))
  (when connect-nodes-supplied-p
    (setf *use-addrman-outgoing* nil)
    (let ((targets (if (equal connect-nodes '("0")) '() (copy-list connect-nodes))))
      (setf *connect-nodes* targets)
      (if targets
          (log-info "Connecting only to -connect peers: ~{~A~^, ~}" targets)
          (log-info "Outbound connections disabled (-connect=0)"))
      (when (and targets (node-added-nodes *node*))
        ;; Core logs the same precedence note for -seednode.
        (log-info "-addnode peers are dialed alongside -connect"))))
  ;; -stopatheight: re-arm the once-only shutdown trigger for this run.
  (setf *stop-at-height-triggered* nil
        *disk-space-abort-triggered* nil)
  ;; Re-arm the shutdown coordination latches: a previous run in the same
  ;; image (tests, an in-REPL restart) leaves them set, and a pre-set
  ;; *shutdown-request* would make the watchdog stop this run immediately.
  (setf *shutdown-request* nil
        *shutdown-complete* nil
        *stop-node-in-progress* nil
        *node-starting* t)
  ;; Trap SIGTERM/SIGINT HERE, before any of the long startup work — not at the
  ;; end of this function. Core does the same: registerSignalHandler runs in
  ;; AppInitBasicSetup (init.cpp:902), a thousand lines before LoadMempool
  ;; (init.cpp:2047). Installed last, every slow startup step ran with SIGTERM
  ;; at its DEFAULT disposition, so a stop during the mempool import, an index
  ;; backfill (hours) or a wallet rescan killed the process outright instead of
  ;; being recorded. Now it registers the request, the loops that poll
  ;; interrupt-requested-p give up at their next boundary, and the watchdog
  ;; services it once this function returns.
  (install-shutdown-handler)
  ;; Periodic peers.dat dump baseline (first dump 15 min from now).
  (setf *last-peers-dump-time* (get-universal-time))
  ;; Core DEFAULT_LOGRATELIMIT / -logratelimit (logging.h:65): on by default, so
  ;; no single log location can fill an operator's disk.
  (setf *log-rate-limit* (and log-rate-limit t)
        *log-rate-window-start* (get-universal-time)
        *log-suppressions-active* nil)
  (clrhash *log-rate-locations*)
  ;; Set before the block store is opened, since the store decides then whether
  ;; to create an xor.dat. The keyword's DEFAULT FORM reads the variable, and a
  ;; &key default form is evaluated at call time — so an omitted argument round
  ;; -trips the variable's own value and only an explicit -flatblockfiles=0/1
  ;; changes it. A literal NIL default here would have pinned every real node to
  ;; the per-block format no matter what the variable said, since this SETF runs
  ;; unconditionally on every start.
  (setf bl.store:*flat-block-files* (and flat-block-files t))
  (log-info "Bitcoin-Lisp Node v~A" (bl.ser:client-version-string))
  (log-info "Network: ~A" network)
  (log-info "Data directory: ~A" (node-data-directory *node*))

  ;; Claim the directory before anything reads or writes it (Core locks the
  ;; datadir and the blocks dir in AppInitMain, init.cpp:1172).
  (lock-data-directory (node-data-directory *node*))

  ;; SIGHUP reopens the log file, so an external logrotate can move it.
  (install-sighup-log-reopen)

  ;; ZMQ notification publishers, if -zmqpub* asked for any. libzmq is loaded
  ;; only at this point and only when there is something to bind, so a host
  ;; without the library runs fine with ZMQ off.
  (when *zmq-publisher-specs*
    (zmq-start-publishers *zmq-publisher-specs*))

  ;; Set prune-after-height for this network
  (setf *prune-after-height* (prune-after-height network))

  ;; Log pruning status
  (when (pruning-enabled-p)
    (if (automatic-pruning-p)
        (log-info "Block pruning: AUTOMATIC (target ~D MiB)" *prune-target-mib*)
        (log-info "Block pruning: MANUAL-ONLY (via pruneblockchain RPC)")))

  ;; Mainnet warnings
  (when (eq network :mainnet)
    (log-warn "*** MAINNET MODE ***")
    (log-warn "You are connecting to the production Bitcoin network.")
    (if *mainnet-relay-enabled*
        (log-info "Transaction relay: ENABLED")
        (log-info "Transaction relay: DISABLED (safety default)")))

  ;; Initialize chain state: the chainstates list starts with the one primary
  ;; chainstate (empty storage suffix, so it loads exactly the files a
  ;; single-chainstate node wrote). A persisted snapshot chainstate would be
  ;; detected and appended here (Core LoadAssumeutxoChainstate) — future work.
  (log-info "Loading chain state...")
  (setf (node-chainstates *node*)
        (list (bl.store:init-chain-state (node-data-directory *node*))))

  ;; Genesis block index entry is ensured after load-header-index below

  (setf *pending-chainstate-recovery* nil)
  (let ((load-result (bl.store:load-state (node-chain-state *node*))))
    (case load-result
      ((:inconsistent)
       ;; A flush was interrupted mid-commit. Don't abort — defer recovery
       ;; until the block store, UTXO cache, and header index are open
       ;; (recover-inconsistent-chainstate needs all three).
       (log-warn "Chainstate in-transition (flush interrupted); will attempt automatic recovery after storage init")
       (push (node-chain-state *node*) *pending-chainstate-recovery*))
      ((t)
       (log-info "Loaded existing chain state: height ~D"
                 (bl.store:current-height (node-chain-state *node*))))
      ((:corrupt)
       ;; The file exists but no format validated, so we cannot say which tip
       ;; the on-disk UTXO set belongs to. Continuing would silently start from
       ;; genesis and replay blocks whose coins are already present, which on
       ;; mainnet trips the BIP30 duplicate-txid check and ends with NO
       ;; best-valid-tip at all — a bricked index that looks like a consensus
       ;; failure. Refuse instead: an operator can reindex or restore, and a
       ;; deterministic startup failure is what the supervisor backs off on
       ;; rather than respawning into the same wall.
       (log-error "chainstate.dat is present but unreadable (failed integrity check).")
       (log-error "Refusing to start: replaying over the existing UTXO set would corrupt the chain index.")
       (log-error "Recover by restoring a backup of chainstate.dat, or reindex from the block files.")
       (error "Corrupt chainstate.dat at ~A" (node-data-directory *node*)))
      ;; NIL means no chainstate file at all — a legitimate first run.
      ((nil)
       (log-info "No chain state on disk; starting from genesis"))))

  ;; Initialize block store
  (log-info "Initializing block storage...")
  (setf (node-block-store *node*)
        (bl.store:init-block-store (node-data-directory *node*)))
  ;; Genesis is never RECEIVED, so nothing else ever writes its body. Core has
  ;; it on disk from initialisation, which is what makes blk00000.dat start at
  ;; height 0 for every reader that walks the block files from outside the node.
  (bl.store:ensure-genesis-on-disk (node-block-store *node*))
  ;; -loadblock=<file>, once the store and chain state exist. Deferred to
  ;; %IMPORT-EXTERNAL-BLOCK-FILES below, which runs after validation is ready.

  ;; Initialize UTXO storage: LevelDB-backed coins-view-cache.
  ;;
  ;; The cache wraps a coins-view-db (LevelDB at <data-dir>/chainstate/).
  ;; Reads pull through from the base on miss; writes accumulate in the
  ;; cache and flush to disk via Phase 2 of do-flush.
  ;;
  ;; First-startup migration: a populated utxoset.dat from a previous
  ;; flat-file version is imported into LevelDB before opening the
  ;; cache. The migration writes a durable marker; once present, we
  ;; never re-migrate (the marker is idempotent and crash-safe).
  (log-info "Initializing UTXO storage (LevelDB-backed)...")
  (let* ((data-dir (node-data-directory *node*))
         (primary (node-chain-state *node*))
         ;; chainstate/ for the primary chainstate (empty storage suffix —
         ;; same directory as always); a snapshot chainstate would open
         ;; chainstate_snapshot/ through the same path function.
         (chainstate-path (namestring
                           (bl.store:chainstate-leveldb-path primary)))
         (utxoset-dat (bl.store:utxo-set-file-path data-dir))
         (migrated-p (bl.store:leveldb-utxo-migration-complete-p
                      chainstate-path)))
    (when (and (not migrated-p) (probe-file utxoset-dat))
      (log-info "Found legacy utxoset.dat; migrating into LevelDB at ~A ..."
                chainstate-path)
      (bl.store:migrate-utxoset-dat-to-leveldb
       utxoset-dat chainstate-path)
      (log-info "Migration complete; LevelDB is now the canonical UTXO store"))
    (let ((view (bl.store:open-coins-view-db chainstate-path)))
      (setf (bl.store:chain-state-coins-view primary)
            (bl.store:make-coins-view-cache view))
      ;; Adopt the stored pointer so a flush before the first block-level
      ;; mutation re-stamps what is already true rather than leaving the coins
      ;; and the pointer to drift apart.
      (bl.store:coins-view-cache-load-best-block
       (bl.store:chain-state-coins-view primary))
      (log-info "UTXO cache opened (base: ~A)" chainstate-path)))

  ;; Load persisted header index if available.
  (multiple-value-bind (loaded corrupt-reason)
      (bl.store:load-header-index (node-chain-state *node*))
    (cond
      (loaded
       (log-info "Loaded persisted header index: ~D entries"
                 (hash-table-count
                  (bl.store::chain-state-block-index
                   (node-chain-state *node*)))))
      ;; A file IS there but did not validate. Starting anyway would leave us
      ;; with an EMPTY block index while chainstate.dat still names a tip: the
      ;; node would claim a height it has no headers for, re-request the whole
      ;; header chain, and on a pruned node could never rebuild the entries
      ;; below the prune horizon from disk. Refuse, exactly as the corrupt
      ;; chainstate.dat branch above does, and as Core's "Error loading block
      ;; database" does for a CBlockTreeDB it cannot read (init.cpp).
      (corrupt-reason
       (log-error "headerindex.dat is present but unreadable: ~A." corrupt-reason)
       (log-error "Refusing to start: an empty block index would contradict the stored chainstate.")
       (log-error "Recover by restoring a backup of headerindex.dat, or reindex from the block files.")
       (error "Corrupt headerindex.dat at ~A" (node-data-directory *node*)))
      ;; No file at all — a legitimate first run.
      (t nil)))

  ;; Genesis FIRST: the reindex below links each record to a parent already in
  ;; the index, so without a root the drain never starts and every record is
  ;; orphaned. See %ENSURE-GENESIS-INDEX-ENTRY.
  (%ensure-genesis-index-entry network)

  ;; -reindex: rebuild the block index from the block files before anything
  ;; reads it. Runs AFTER the header index load so an intact index is simply
  ;; extended rather than discarded — reindexing is additive, and a node that
  ;; threw away a good index to rebuild it would be strictly worse off if the
  ;; files turned out to be incomplete.
  (when (and reindex (node-block-store *node*))
    (log-info "Reindex: rebuilding the block index from the block files...")
    (multiple-value-bind (added orphans)
        (bl.store:reindex-block-index
         (node-block-store *node*) (node-chain-state *node*))
      (log-info "Reindex: added ~D block index entries~@[, ~D record~:P had no parent~]"
                added (and (plusp orphans) orphans))
      (when (plusp added)
        (bl.store:save-header-index (node-chain-state *node*)
                                                :force-full t))))

  ;; Per-file accounting for the flat block files, recovered by joining the
  ;; store's hash -> position map with the header index's hash -> height. It
  ;; has to happen HERE: the store is opened before the header index is loaded,
  ;; so neither half knows enough on its own, and without it no flat file can
  ;; ever be shown to lie inside the prunable window.
  (when (node-block-store *node*)
    (let ((files (bl.store:rebuild-block-file-info
                  (node-block-store *node*) (node-chain-state *node*))))
      (when (plusp files)
        (log-info "Block file accounting: ~D flat block file~:P" files))))



  ;; Snapshot chainstate startup handling (Core LoadChainstate ordering,
  ;; node/chainstate.cpp:151-238). -reindex-chainstate deletes a snapshot
  ;; chainstate outright (Core wipe_chainstate_db) — the primary then
  ;; rebuilds from stored blocks with no target. Otherwise, detect a
  ;; persisted snapshot chainstate dir and re-init dual chainstates. Runs
  ;; after the header index is loaded (the base entry must resolve) and
  ;; before crash-recovery resolution below (a torn snapshot flush joins the
  ;; pending-recovery list).
  (if reindex-chainstate
      (when (bl.store:find-assumeutxo-chainstate-dir
             (node-data-directory *node*))
        (log-info "[snapshot] deleting snapshot chainstate due to reindexing")
        (bl.store:delete-snapshot-chainstate-files
         (node-data-directory *node*)))
      (load-snapshot-chainstate *node*))

  ;; Resolve interrupted-flush chainstates now that the block store, UTXO
  ;; caches, and header index are all available. Only abort (resync) if the
  ;; on-disk state needed to recover is gone.
  (let ((pending *pending-chainstate-recovery*))
    (setf *pending-chainstate-recovery* nil)
    (dolist (cs pending)
      (unless (recover-inconsistent-chainstate *node* cs)
        (error "chainstate inconsistent and unrecoverable: move ~A aside and re-sync"
               (node-data-directory *node*)))))

  ;; Assumeutxo P5: if a persisted historical chainstate already reached the
  ;; snapshot base on a previous run, re-prove the commitment hash now and, on
  ;; success, consolidate the LevelDB dirs so the validated snapshot chainstate
  ;; becomes the sole chainstate (Core LoadChainstate's MaybeValidateSnapshot +
  ;; ValidatedSnapshotCleanup, node/chainstate.cpp:196-235). Runs after
  ;; crash-recovery (the historical tip must be settled) and before the undo /
  ;; index init below, which then bind the single promoted chainstate.
  (finalize-snapshot-validation-at-startup *node*)

  ;; Initialize undo data persistence
  ;; ALWAYS the legacy per-block directory. INITIALIZE-UNDO-STORAGE's argument
  ;; is not "where undo lives" — it is specifically the legacy per-block
  ;; directory, and Core's revNNNNN.dat records are addressed through the BLOCK
  ;; STORE and chain state instead (a rev record is found by the block index
  ;; entry that points at it, never by scanning a directory).
  ;;
  ;; #466 briefly routed this through a DATADIR-UNDO-PATH resolver that
  ;; preferred blocks/ whenever blocks/ held anything. blocks/ ALWAYS holds
  ;; something — the block files — so on a real testnet4 node it moved the undo
  ;; directory to blocks/ while 154,198 legacy per-block records sat in undo/,
  ;; making every one of them unreachable. A reorg would then have been unable
  ;; to disconnect any of those blocks. Caught within minutes by reading the
  ;; live node's log; the resolver was deleted rather than repaired, because
  ;; "which directory" was never the right question here.
  (let ((undo-path (merge-pathnames "undo/" (node-data-directory *node*))))
    ;; The store and chain state are what enable Core's rev-file undo format:
    ;; a rev record is addressed only by the block index entry that points at
    ;; it, and reading one needs the block to name its coins.
    (bl.val:initialize-undo-storage
     undo-path
     :block-store (node-block-store *node*)
     :chain-state (node-chain-state *node*))
    (log-info "Undo data directory: ~A" undo-path))

  ;; Catch-up sweep: drop undo files at/below the pruned horizon. They
  ;; accumulated before undo pruning existed (53GB/500k files on the first
  ;; mainnet run); after the first sweep the directory only holds the
  ;; unpruned window, so this is cheap on every later start. The undo
  ;; directory is shared across chainstates, so the horizon is the MINIMUM
  ;; pruned-height over all of them: during an assumeutxo background sync the
  ;; current (snapshot) chainstate's cursor sits above the base while the
  ;; historical chainstate still needs its own undo window far below it.
  (when (pruning-enabled-p)
    (let ((swept (bl.val:prune-stale-undo-files
                  (node-chain-state *node*)
                  :horizon (reduce #'min (node-chainstates *node*)
                                   :key #'bl.store:chain-state-pruned-height))))
      (when (plusp swept)
        (log-info "Pruned ~D stale undo file~:P below the prune horizon" swept))))

  ;; Optional chainstate reindex: rebuild the UTXO set from stored blocks
  ;; before the indexes initialize (so they rebuild against the fresh set) and
  ;; before the sync thread starts (single-threaded here, no writer races).
  ;; Runs after the block index + undo storage are ready.
  (when reindex-chainstate
    (do-reindex-chainstate))

  ;; Initialize recent rejects filter (DoS protection)
  (setf (node-recent-rejects *node*) (make-rejects-filter))

  ;; Initialize mempool
  (log-info "Initializing mempool...")
  (setf (node-mempool *node*) (bl.mp:make-mempool))

  ;; Initialize fee estimator
  (log-info "Initializing fee estimator...")
  (setf (node-fee-estimator *node*)
        (bl.mp:make-fee-estimator
         :data-directory (node-data-directory *node*)))
  ;; Load persisted fee stats
  (bl.mp:load-fee-stats (node-fee-estimator *node*))

  ;; Core's CBlockPolicyEstimator, which learns from how long each feerate
  ;; actually waited rather than from a percentile of what miners took. The
  ;; mempool and connect-block report into it through this one binding.
  (setf bl.mp:*block-policy-estimator*
        (bl.mp:make-block-policy-estimator))

  ;; The RPC server comes up HERE — before the mempool replay and the index
  ;; catch-ups below, which is Core's order: AppInitServers (which starts the
  ;; HTTP/RPC server) runs long before LoadMempool and the index sync
  ;; (init.cpp:750-760 vs the import thread). Every request answers
  ;; RPC_IN_WARMUP (-28) with the current status until start-node finishes.
  ;;
  ;; This is the fix for a real outage: an 83 MB mempool.dat turned a restart
  ;; into a ~45-minute window in which the node was alive, working, and
  ;; completely unreachable — bitcoin-cli got connection refused and the
  ;; monitoring saw a dead node. It now gets "-28 Replaying mempool...", which
  ;; is retryable and true.
  (when rpc-port
    (%start-rpc-early *node* rpc-port rpc-bind rpc-bind-supplied-p
                      rpc-user rpc-password rpc-auth rpc-allow-ip
                      rest-enabled network webui webui-supplied-p
                      webui-path webui-open))

  ;; Reload the persisted mempool through normal acceptance (Core LoadMempool)
  (bl.rpc:set-rpc-warmup-status "Replaying mempool...")
  (load-mempool-from-disk *node*)

  ;; Initialize peer address book
  (log-info "Loading peer address book...")
  (setf (node-address-book *node*) (bl.net:make-address-book))
  (let ((peers-path (bl.net:peers-dat-path (node-data-directory *node*))))
    (when (bl.net:load-address-book (node-address-book *node*) peers-path)
      (log-info "Loaded peer address book: ~D entries"
                (bl.net:address-book-count (node-address-book *node*)))))

  ;; Manual banlist persistence (Core BanMan <datadir>/banlist.json): load
  ;; previous bans (expired entries swept) and point future mutations at the
  ;; file — every setban/clearbanned dumps it immediately, like Core.
  (setf bl.net:*banlist-path*
        (merge-pathnames "banlist.json" (node-data-directory *node*)))
  (let ((n (bl.net:load-banlist)))
    (when (and n (plusp n))
      (log-info "Loaded ~D banned address~:P from banlist.json" n)))

  ;; Load reconnection anchors (tried first, before DNS seeds — anti-eclipse).
  (load-anchors *node*)

  ;; Reconcile chainstate.dat with where the coins actually are.
  ;;
  ;; These are two records of one fact and every corruption story here is them
  ;; disagreeing: an interrupted reorg rewinds coins while chainstate.dat still
  ;; names the old tip. The coins DB's pointer moves WITH the coins, so it is
  ;; the fact and the tip record is the stale copy — move the record, then let
  ;; normal sync re-validate the gap. This runs unconditionally, unlike the
  ;; older in-transition recovery, because the case that motivated it leaves no
  ;; marker at all: an interrupted reorg whose cache is then flushed cleanly.
  (when (eq :unresolvable (reconcile-coins-db-best-block *node*))
    (log-error "Refusing to start: the UTXO set names a block this node cannot place.")
    (log-error "Recover by reindexing from the block files, or restore a backup.")
    (error "Unplaceable UTXO set in ~A" (node-data-directory *node*)))

  ;; Step 8 of Core's init (indexes): open every enabled index and catch it
  ;; up over the blocks already on disk before the sync thread starts.
  (%start-indexes txindex blockfilterindex txospenderindex coinstatsindex
                  reindex-chainstate)

  ;; -forcecompactdb: once every LevelDB is open (and any reindex/backfill has
  ;; run), full-compact them to reclaim tombstone space -- e.g. the ~24M delete
  ;; markers a reindex-chainstate wipe leaves behind. Bitcoin Core does the same
  ;; via CDBWrapper force_compact when -forcecompactdb is set.
  (when force-compact-db
    (force-compact-databases))

  ;; BIP157 filter serving (-peerblockfilters): gated above on the block filter
  ;; index being enabled; advertised as NODE_COMPACT_FILTERS in our version.
  (setf bl:*peer-block-filters* (and peer-block-filters t))
  (when peer-block-filters
    (log-info "BIP157 compact filter serving enabled (NODE_COMPACT_FILTERS)"))

  ;; BIP330 Erlay handshake (-txreconciliation; Core DEBUG_ONLY, default off).
  ;; Negotiates sendtxrcncl + per-peer salt storage only — no sketch exchange
  ;; exists at Core ref d3056bc either.
  (setf bl:*tx-reconciliation* (and tx-reconciliation t))
  (when tx-reconciliation
    (log-info "BIP330 transaction reconciliation handshake enabled (sendtxrcncl)"))

  ;; BIP324 v2 transport opt-in. Effective only if libsecp256k1 has the
  ;; ellswift module (probed lazily per connection via v2-available-p).
  (setf bl.net:*v2-transport-enabled* (and v2transport t))
  (when v2transport
    (log-info "BIP324 v2 transport enabled (~:[ellswift NOT available -- will run v1 only~;active~])"
              (bl.net:v2-available-p)))

  ;; Initialize secp256k1
  (log-info "Initializing cryptographic context...")
  (bl.crypto:ensure-secp256k1-loaded)

  ;; Wallet support (wallet P1). Default: enabled everywhere except mainnet,
  ;; where holding keys on an internet-facing node is the operator's explicit
  ;; opt-in (-wallet), mirroring the relay/-webui safety pattern.
  (let ((wallet-enabled (if wallet-supplied-p
                            (and wallet t)
                            (not (eq network :mainnet)))))
    (when wallet-enabled
      (setf (node-wallet-manager *node*)
            (bl.rpc:init-wallet-manager (node-data-directory *node*)
                                                  network))
      (log-info "Wallet support enabled (descriptor wallets under ~A)"
                (merge-pathnames "wallets/" (node-data-directory *node*)))
      ;; Core LoadWallets (load.cpp:118): load every wallet recorded for
      ;; startup in settings.json. Runs here because the chainstate (above)
      ;; and the mempool (load-mempool-from-disk) are both up, so each wallet
      ;; can catch up from its locator and fold in the mempool; networking has
      ;; not started, so no block can connect underneath the catch-up.
      (bl.rpc:load-wallets-on-startup *node* wallet-names)))

  (setf (node-running *node*) t)

  ;; The RPC server is UP by now (see %start-rpc-early above); the node is
  ;; ready, so stop answering -28.
  (bl.rpc:finish-rpc-warmup)
  (when rpc-port
    (log-info "RPC server ready"))

  ;; -startupnotify, once the node is actually up (Core init.cpp:529).
  (dolist (command startup-notify)
    (run-notify-command command))

  ;; Connect to peers and sync if requested (in background thread)
  ;; Reconnects and retries when peers are lost, similar to Bitcoin Core's
  ;; CheckForStaleTipAndEvictPeers (net_processing.cpp:5460)
  (when sync
    (bl.net:reset-ibd-stop)
    (bl.net:reset-tx-requests)
    (bl.net:reset-initial-broadcast-schedule)
    ;; Fresh recent-confirmed filter (Core builds it per process; covers
    ;; in-image restarts).
    (bl.val:reset-recent-confirmed)
    ;; Seed the durable at-tip liveness signal (item #6) so a freshly-started,
    ;; already-at-tip node reports healthy on /rest/health before its first new
    ;; block. last-tip-height starts at the current tip so only genuine advances
    ;; bump the timestamp.
    (let ((cs (node-current-chainstate *node*)))
      (setf (node-last-tip-advance-time *node*) (bl.ser:get-node-time)
            (node-last-tip-height *node*)
            (if cs (bl.store:current-height cs) 0)))
    (setf (node-sync-thread *node*)
          (bt:make-thread
           (lambda ()
             (handler-case
                 (progn
                   ;; Initial connection. Guarded on its own so a startup dial
                   ;; failure logs and defers to the loop's reconnect path
                   ;; instead of ending the thread (a dead sync thread with
                   ;; node-running still T is a socket-reading zombie).
                   ;; -seednode first: its whole purpose is to fill the
                   ;; address book BEFORE the dial that reads it. Guarded
                   ;; separately so an unreachable seed never costs us the
                   ;; startup dial.
                   (handler-case
                       (connect-seed-nodes *node*)
                     (error (c)
                       (log-error "-seednode address fetch failed: ~A" c)))
                   (handler-case
                       (connect-to-peers *node* max-peers :timeout 60 :min-peers 2)
                     (error (c)
                       (log-error "Initial peer connection failed (retrying in loop): ~A" c)))
                   ;; Sync + follow-tip loop runs until node shutdown. The
                   ;; previous early-return on "sync complete" exited the only
                   ;; thread reading from peer sockets, so live tip
                   ;; announcements after IBD were never processed. Peers push
                   ;; new tips via sendheaders (BIP 130); this 30s poll is the
                   ;; backstop for inv-only peers and missed announcements.
                   (loop while (node-running *node*)
                         ;; Per-iteration error containment (item #5): a
                         ;; transient error must retry the loop, never unwind
                         ;; out of it and end the thread. handler-bind logs a
                         ;; live-stack backtrace at the error site; the
                         ;; enclosing handler-case then unwinds to the short
                         ;; backoff + retry in its error clause below.
                         do (handler-case
                                (handler-bind
                                    ((error
                                       (lambda (c)
                                         (log-error "Sync thread error: ~A" c)
                                         #+sbcl
                                         (let ((bt (with-output-to-string (s)
                                                     (sb-debug:print-backtrace
                                                      :stream s :count 50))))
                                           (log-error "Sync thread backtrace:~%~A" bt)))))
                                  (merge-inbound-peers *node*)
                            ;; Maintain manually-added peers each cycle (addnode).
                            (connect-added-nodes *node*)
                            (cond
                              ((>= (length (node-peers *node*)) 1)
                               (setf (node-syncing *node*) t)
                               (unwind-protect
                                    (sync-blockchain *node*)
                                 (setf (node-syncing *node*) nil))
                               ;; Durable at-tip liveness signal (item #6):
                               ;; record a tip advance whenever this sync pass
                               ;; raised the active-chain height.
                               (note-node-tip-progress *node*)
                               ;; Full peer maintenance, not just replacement:
                               ;; health checks + outgoing pings, addnode
                               ;; retry, slot refill, dedicated block-relay
                               ;; slots, and feeler probes. maintain-peers was
                               ;; previously dead code — nothing called it, so
                               ;; the PR #216 block-relay/feeler conns and
                               ;; ping-timeout eviction never ran live.
                               (maintain-peers *node*)
                               ;; Periodic peers.dat dump (Core DumpAddresses
                               ;; every 15 min); cadence-gated inside.
                               (maybe-dump-peer-addresses *node*)
                               ;; ⚠️ The SLEEP runs BEFORE the pump, so a message
                               ;; that arrives just after one pass waits out the
                               ;; whole tick before anything reads it. At one
                               ;; second a tick that is the floor on how fast an
                               ;; announced block can be noticed, and a
                               ;; propagation spans two of them — which is the
                               ;; flat 2s diag/propagation_probe.py still
                               ;; measures after #507 removed the header round
                               ;; trip.
                               ;;
                               ;; Sub-second ticks, with the same 30s ceiling and
                               ;; the same per-second cadence for everything that
                               ;; wants one: the trickle, ping and dump work below
                               ;; is gated on SECOND changing, so it keeps its
                               ;; period while the pump gets to run sooner.
                               ;; Core's ProcessMessages runs continuously; this
                               ;; is the same direction, bounded.
                               (loop for tick from 1 to (* 30 +sync-ticks-per-second+)
                                     for second = (ceiling tick +sync-ticks-per-second+)
                                     while (node-running *node*)
                                     do (sleep (/ 1 +sync-ticks-per-second+))
                                        ;; Retry buffered unsent bytes on
                                        ;; every peer (non-blocking) — the
                                        ;; periodic half of Core's
                                        ;; SocketSendData.
                                        (bl.net:flush-peer-send-buffers
                                         (node-peers *node*))
                                        ;; Steady-state receive pump: drain
                                        ;; every peer's readable messages
                                        ;; with the full node context. This
                                        ;; loop used to be a pure 30s sleep
                                        ;; — a receive dead window in which
                                        ;; pings, invs, and getdata for txs
                                        ;; we had JUST announced sat unread
                                        ;; (Core's per-peer ProcessMessages
                                        ;; runs continuously). A new header
                                        ;; announcement ends the wait so the
                                        ;; block is fetched immediately.
                                        (let* ((cs (node-current-chainstate *node*))
                                               (pump (bl.net:pump-peer-messages
                                                      (node-peers *node*)
                                                      (node->context *node* cs)
                                                      nil)))
                                          ;; Tx-request scheduler: send
                                          ;; delayed announcements now due,
                                          ;; and re-route requests that
                                          ;; expired (60s) to another
                                          ;; announcer (Core GetRequestsToSend
                                          ;; runs per SendMessages pass).
                                          (bl.net:process-tx-requests)
                                          (bl.net:retry-timed-out-tx-requests)
                                          ;; Trickled tx announcements: drain
                                          ;; due per-peer inv queues each
                                          ;; second (Poisson schedules inside;
                                          ;; Core SendMessages runs its
                                          ;; equivalent on every message pump).
                                          (bl.net:flush-tx-announcements
                                           (node-peers *node*)
                                           (node-mempool *node*))
                                          ;; Locally-submitted txs still in the
                                          ;; unbroadcast set get re-announced
                                          ;; every 10-15 min until a peer's
                                          ;; getdata confirms propagation (Core
                                          ;; ReattemptInitialBroadcast).
                                          (bl.net:maybe-reattempt-initial-broadcast
                                           (node-peers *node*)
                                           (node-mempool *node*))
                                          ;; Wallet rebroadcast timer (Core
                                          ;; MaybeResendWalletTxs on the
                                          ;; scheduler, every minute): each
                                          ;; wallet resubmits its unconfirmed
                                          ;; txs past a randomized 12-36h
                                          ;; deadline. Cadence-gated inside;
                                          ;; takes node-lock -> wallet-lock
                                          ;; per tx, so it must run OUTSIDE
                                          ;; any node-lock hold (wallet P4).
                                          (bl.rpc:wallets-maybe-resend *node*)
                                          ;; Local-address self-advertisement
                                          ;; (our onion address, once torcontrol
                                          ;; registers it): per-peer ~24h Poisson
                                          ;; schedule inside, no-op while the
                                          ;; local-address map is empty or in
                                          ;; IBD (Core MaybeSendAddr).
                                          (bl.net:maybe-advertise-local-address
                                           (node-peers *node*)
                                           (node-chain-state *node*))
                                          ;; BIP133 feefilter refresh (Core
                                          ;; MaybeSendFeefilter on the message
                                          ;; loop): per-peer ~10min Poisson
                                          ;; schedule inside, so this is a
                                          ;; cheap no-op most ticks. Runs on
                                          ;; the sync thread, which is why
                                          ;; its RNG use is safe.
                                          (let ((cs (node-chain-state *node*))
                                                (mp (node-mempool *node*))
                                                (now (bl.ser:get-unix-time)))
                                            (dolist (p (node-peers *node*))
                                              (when (eq (bl.net:peer-state p) :ready)
                                                (ignore-errors
                                                 (bl.net:maybe-send-feefilter
                                                  p mp cs now))
                                                ;; BIP-330: open a reconciliation
                                                ;; round with one peer at a time.
                                                ;; Inert unless -txreconciliation
                                                ;; is set and the peer completed
                                                ;; the handshake.
                                                (ignore-errors
                                                 (bl.net:maybe-start-reconciliation
                                                  p now)))))
                                          ;; New headers announced: start the
                                          ;; next sync cycle now to fetch the
                                          ;; block instead of waiting out the
                                          ;; 30s poll.
                                          ;; Record a tip advance observed this
                                          ;; second (item #6 durable liveness).
                                          (note-node-tip-progress *node*)
                                          (when (plusp (bl.net:ibd-context-headers-received pump))
                                            (return))
                                          ;; BEHIND: we hold headers above our
                                          ;; own tip, so there is known work.
                                          ;; Sitting out the rest of the 30s
                                          ;; poll here is pure latency — the
                                          ;; headers arrived during the sync
                                          ;; pass, not during this wait, so
                                          ;; the new-headers exit above never
                                          ;; fires and the retry waits a full
                                          ;; cycle.
                                          ;;
                                          ;; Measured: two regtest nodes, five
                                          ;; blocks, one announcement — 40
                                          ;; seconds to converge, of which ~24
                                          ;; were this wait. Core's tests allow
                                          ;; 60s for a full sync, so that alone
                                          ;; puts most multi-node tests on the
                                          ;; edge.
                                          ;;
                                          ;; Bounded rather than immediate:
                                          ;; leave only after +BEHIND-RETRY-
                                          ;; SECONDS+ so a chain no peer can
                                          ;; serve retries on a timer instead
                                          ;; of spinning. That case is real —
                                          ;; it is what the download loop's own
                                          ;; no-progress yield exists for.
                                          (when (and (>= second +behind-retry-seconds+)
                                                     (> bl.net:*highest-header-seen*
                                                        (bl.store:current-height cs)))
                                            (return)))))
                              (t
                               ;; No peers. Before waiting for one, connect
                               ;; whatever is ALREADY on disk: after a -reindex
                               ;; the whole chain can be indexed with the
                               ;; chainstate still at genesis, and with
                               ;; -connect=0 no peer will ever arrive to
                               ;; trigger it. Core rebuilds entirely from disk
                               ;; in that situation (ActivateBestChain runs
                               ;; from startup, not only on an arriving block),
                               ;; and an operator recovering a corrupted
                               ;; chainstate offline is exactly who needs it.
                               ;;
                               ;; Cheap when there is nothing to do: it returns
                               ;; immediately once the tip IS the most-work
                               ;; candidate, which is the steady state.
                               (let ((switched
                                       (ignore-errors
                                        (bl.val:activate-best-chain
                                         (node-current-chainstate *node*)
                                         (node-block-store *node*)
                                         (bl.store:chain-state-coins-view
                                          (node-current-chainstate *node*))
                                         :fee-estimator (node-fee-estimator *node*)
                                         :mempool (node-mempool *node*)))))
                                 (cond
                                   (switched
                                    (note-node-tip-progress *node*))
                                   (t
                                    (log-warn "No peers available, reconnecting in 5s...")
                                    (loop repeat 5 while (node-running *node*)
                                          do (sleep 1))
                                    (connect-to-peers *node* max-peers
                                                      :timeout 30 :min-peers 1)))))))
                              (error (c)
                                ;; Transient iteration error: the backtrace was
                                ;; already logged above (live stack). Log a
                                ;; summary, short-backoff, and RETRY the loop
                                ;; rather than let the error end the thread.
                                (log-error "Sync thread iteration error (retrying): ~A" c)
                                (loop repeat 5 while (node-running *node*)
                                      do (sleep 1))))))
               (error () nil)))
           :name "bitcoin-sync-thread")))

  ;; DNS seeding, at Core's place in the sequence: ThreadDNSAddressSeed is
  ;; started (or declined) here, with connman, and is INDEPENDENT of -connect
  ;; (net.cpp:3520-3527). Ours used to live inside CONNECT-TO-PEERS, behind a
  ;; "do we want more addresses" test, which had two consequences:
  ;;
  ;;   - the `disabled' line never reached a node that had enough addresses,
  ;;     or one that never got that far — which is every node the test
  ;;     framework starts, since it passes -connect;
  ;;   - a node running -connect WITH an explicit -dnsseed=1 never queried the
  ;;     seeds at all, because under -connect that path only dials the
  ;;     configured peers.
  ;;
  ;; The soft-set rule already makes -dnsseed=0 the default under -connect
  ;; (config.lisp), so the only nodes this reaches are the ones that asked.
  ;; Results go into the ADDRESS BOOK, which is what Core's thread does — not
  ;; into one dial's candidate list, which is what the old placement did.
  (if *dns-seed-enabled*
      (%seed-address-book-from-dns *node*)
      (log-info "DNS seeding disabled (-dnsseed=0)"))

  ;; Inbound listening (depends on the sync thread to merge accepted peers).
  (when (and sync listen)
    (start-inbound-listener *node* listen-bind))

  ;; Tor onion service (-listenonion, default on like Core): a loopback
  ;; listener the local Tor daemon forwards inbound onion connections to,
  ;; plus the torcontrol client that registers the v3 onion service and
  ;; AddLocal()s the .onion address for self-advertisement. Gated on LISTEN
  ;; (Core: -listen=0 soft-disables -listenonion; the config layer errors on
  ;; the explicit combination). Divergence from Core noted: Core binds its
  ;; onion listener whenever it listens, even with -listenonion=0 — we only
  ;; bind it when the service can actually exist.
  (when (and sync listen listen-onion)
    (bl.net:clear-local-addresses)
    (start-onion-listener *node*)
    (setf (node-tor-controller *node*)
          (bl.net:start-tor-control
           :control-spec tor-control
           :password tor-password
           :data-directory (node-data-directory *node*)
           :virtual-port (network-port network)
           :target-port (onion-listen-port *node*))))

  ;; -externalip: advertise the given addresses as our own (Core
  ;; init.cpp:1803-1808: AddLocal(addr, LOCAL_MANUAL) at the listen port).
  ;; Validated resolvable above; runs after the tor block so its
  ;; clear-local-addresses cannot wipe these entries.
  (dolist (spec bl.net:*external-ips*)
    (multiple-value-bind (net bytes)
        (bl.net:parse-network-address spec)
      (when net
        (bl.net:add-local
         net bytes (listen-port network)
         bl.net:+local-manual+))))

  ;; -loadblock=<file>: import external block files before declaring the node
  ;; up, as Core does (ImportBlocks runs on the init thread and the RPC waits
  ;; on it). A file that cannot be opened warns and the rest still run.
  (%import-external-block-files *node* load-block)

  ;; Startup is over: a stop arriving from here on has a fully-built node to
  ;; tear down, so the handler's no-watchdog fallback may run stop-node inline
  ;; again (REPL / embedded use).
  (setf *node-starting* nil)
  (log-info "Node started successfully")
  *node*)

(defun %import-external-block-files (node paths)
  "Import every file in PATHS through the ordinary consensus path (Core
ImportBlocks' -loadblock loop, node/blockstorage.cpp:1296-1309).

Blocks in such a file are in whatever order the producer wrote them, and Core
skips one whose parent it does not know yet rather than parking it — the parking
map is passed only by -reindex, not by -loadblock (validation.cpp:4993-5056).
A second pass is therefore how an out-of-order file gets fully imported, and
that is Core's behaviour too; contrib/linearize writes height order, so the
common case is one pass.

Every block is validated exactly as a network block would be: this imports
blocks, it does not trust them."
  (dolist (path (if (listp paths) paths (list paths)))
    (let ((file (probe-file path)))
      (cond
        ((null file)
         (log-warn "Could not open blocks file ~A" path))
        (t
         (log-info "Importing blocks file ~A..." (namestring file))
         (let ((loaded 0) (accepted 0))
           (handler-case
               (bl.store:map-external-block-file
                file
                (lambda (bytes)
                  (incf loaded)
                  (let ((block (handler-case
                                   (bl.ser:br-read-bitcoin-block
                                    (bl.ser:make-byte-reader-from bytes))
                                 (error () nil))))
                    (when block
                      (multiple-value-bind (ok reason)
                          (bl.rpc::%activate-submitted-block node block)
                        (declare (ignore reason))
                        (when ok (incf accepted)))))))
             (error (e)
               (log-warn "Importing blocks file ~A stopped: ~A" (namestring file) e)))
           (log-info "Imported ~D of ~D block~:P from ~A"
                     accepted loaded (namestring file))))))))

(defun %check-datadir-option (cli)
  "An explicitly named -datadir that does not exist is FATAL, as it is in Core
 (CheckDataDirOption, args.cpp:789-793; the error is \"specified data directory
... does not exist\").

We created it instead. On a node that is the wrong default in both directions
an operator hits it: a typo and an unmounted volume both present as an empty
directory, and an empty datadir means a full re-sync from genesis — started
silently, and on mainnet measured in days. Not naming -datadir at all is still
fine; that is the default path, and creating THAT is the intended behaviour."
  (let ((datadir (cdr (assoc "datadir" cli :test #'string=))))
    (when (and datadir (plusp (length datadir)))
      (let ((path (pathname (if (char= (char datadir (1- (length datadir))) #\/)
                                datadir
                                (concatenate 'string datadir "/")))))
        (unless (probe-file path)
          (error 'bl::config-parse-error
                 :message (format nil "specified data directory \"~A\" does not exist"
                                  datadir)))))))

(defun %read-config-includes (conf-text cli datadir)
  "Resolve -includeconf, returning the list of config texts to merge (the main
file first). Core ArgsManager::ReadConfigFiles, common/config.cpp:150-213.

Ours was unimplemented: a split configuration loaded with everything at
defaults after a single warning line, which on a node is indistinguishable from
a config file that was read and understood.

Core's rules, all of which apply here:
  - the include list is read from the network section AND the global area;
  - a relative path is relative to the base datadir (net_specific=false);
  - a missing or unreadable include is a FATAL error, not a warning — the
    alternative is silently running without the settings it holds;
  - -includeconf inside an INCLUDED file is ignored with a warning, so a config
    cannot recurse;
  - on the command line only the negated form is accepted, and -noincludeconf
    suppresses includes entirely."
  (when (null conf-text)
    (return-from %read-config-includes nil))
  (let ((cli-include (assoc "includeconf" cli :test #'string=)))
    (when (and cli-include (not (bl::conf-parse-bool (cdr cli-include))))
      ;; -noincludeconf
      (return-from %read-config-includes (list conf-text)))
    (when (and cli-include (bl::conf-parse-bool (cdr cli-include)))
      (error 'bl::config-parse-error
             :message "-includeconf cannot be used from the command line; put it ~
                       in the configuration file")))
  (let* ((network (bl::resolve-network-from-config
                   (append cli (bl::conf-global-entries conf-text))))
         (entries (bl::parse-bitcoin-conf conf-text network))
         (names (loop for (k . v) in entries
                      when (and (string= k "includeconf") (plusp (length v)))
                        collect v))
         (base (pathname (if (and (plusp (length datadir))
                                  (char= (char datadir (1- (length datadir))) #\/))
                             datadir
                             (concatenate 'string datadir "/"))))
         (texts (list conf-text)))
    (dolist (name names)
      (let ((path (merge-pathnames name base)))
        (unless (probe-file path)
          (error 'bl::config-parse-error
                 :message (format nil "Failed to include configuration file ~A" name)))
        (let ((text (alexandria:read-file-into-string path)))
          ;; A recursive include is dropped with a warning, exactly as Core
          ;; does (it re-scans for includeconf after reading and prints
          ;; "-includeconf cannot be used from included files").
          (dolist (inner (bl::parse-bitcoin-conf text nil))
            (when (string= (car inner) "includeconf")
              (log-warn "-includeconf cannot be used from included files; ~
                         ignoring -includeconf=~A" (cdr inner))))
          (log-info "Included configuration file ~A" name)
          (push text texts))))
    (nreverse texts)))

(defun %network-subdirectory (network)
  "The per-network subdirectory of the datadir, as Bitcoin Core defines it
 (CreateBaseChainParams, chainparamsbase.cpp:40-55). NIL means the datadir root.

  mainnet   -> the root        testnet3 -> testnet3/
  testnet4  -> testnet4/       signet   -> signet/       regtest -> regtest/

Ours used to be the INVERSE for exactly the two that matter: mainnet in
`mainnet/` and testnet3 at the root. Pointing our node at a Core datadir with
the default network therefore wrote testnet3 data into Core's MAINNET
directory, and pointing Core at ours found nothing and started a fresh sync."
  (bl.chain:chain-params-data-subdirectory (bl.chain:find-chain-params network)))

(defun network-data-path (base-path network)
  "Where NETWORK's data lives under BASE-PATH.

Core's layout, with one deliberate exception: a datadir that already holds data
in our OLD layout keeps using it. Silently adopting Core's layout on an existing
node would present an empty datadir to a node that has one — which on mainnet
means discarding a synced chain and starting IBD from genesis, the single most
expensive way to be wrong here. The legacy directory is logged every start so it
is visible rather than inherited by accident."
  (let* ((subdir (%network-subdirectory network))
         (core-path (if subdir (merge-pathnames subdir base-path) base-path))
         ;; The layout this tree used before: mainnet under mainnet/, testnet3
         ;; at the root. Every other network already agreed with Core.
         (legacy-subdir (and (eq network :mainnet) "mainnet/"))
         (legacy-path (if legacy-subdir
                          (merge-pathnames legacy-subdir base-path)
                          base-path)))
    (cond
      ((equal core-path legacy-path) core-path)
      ;; "Holds data" means a chainstate, not merely an existing directory —
      ;; ensure-directories-exist creates empty ones freely.
      ((and (not (probe-file (merge-pathnames "chainstate.dat" core-path)))
            (probe-file (merge-pathnames "chainstate.dat" legacy-path)))
       (log-warn "Using the legacy data layout ~A for ~A; Bitcoin Core's layout ~
                  for this network is ~A. Move the directory to adopt it."
                 legacy-path network core-path)
       legacy-path)
      (t core-path))))

(defun %settings-file-path (scope datadir network)
  "Where the read-write settings file lives, or NIL when -nosettings turned it
off (Core ArgsManager::GetSettingsPath).

Default is settings.json in the NETWORK directory, not the datadir root — on
regtest that is <datadir>/regtest/settings.json, which is the path the
functional tests compute as `node.chain_path / \"settings.json\"`. An explicit
-settings= is taken relative to the DATADIR, as Core does.

SCOPE is the command line followed by the config file's sections and globals,
in precedence order — -settings is an ordinary option and can be set in
bitcoin.conf like any other (feature_settings.py drives exactly that with a
`nosettings=1` appended to the [regtest] section). It cannot come from the
settings file itself, which is why SCOPE is assembled here rather than taken
from the merged config."
  (let ((value (cdr (assoc "settings" scope :test #'string=))))
    (cond
      ;; -nosettings arrives as "0" from PARSE-CLI-ARGS' negation handling.
      ((and value (string= value "0")) nil)
      ((and value (not (string= value "1")))
       (merge-pathnames value (pathname datadir)))
      (t (merge-pathnames "settings.json"
                          (network-data-path (pathname datadir) network))))))

(defun %read-settings-file (path)
  "The settings file at PATH as an alist, or NIL when there is none.

A malformed file ABORTS startup, exactly as Core does (common/init.cpp:99-108
turns a failed ReadSettingsFile into a fatal ConfigError). Starting anyway with
the file ignored would run the node on settings the operator cannot see in it."
  (unless (probe-file path)
    (return-from %read-settings-file nil))
  (multiple-value-bind (alist errors)
      (bl:parse-settings-json
       (handler-case (alexandria:read-file-into-string path)
         (error (e)
           (error "Settings file could not be read: ~A. Please check permissions." e)))
       (namestring path))
    (when errors
      (error "Settings file could not be read: ~{~A~^; ~}" errors))
    (let ((invalid (bl:validate-settings-values alist)))
      (when invalid (error "~A" invalid)))
    (dolist (name (bl:unknown-settings-keys alist))
      (defer-log :warn "Ignoring unknown rw_settings value ~A" name))
    alist))

(defun %write-settings-file (path alist)
  "Rewrite PATH with ALIST plus Core's warning comment.

Temp file, fsync, rename, fsync the directory — the same discipline
BITCOIN-LISP.RPC::%WRITE-SETTINGS uses for the wallet half of this very file.
Core writes it through a temp and a rename too (args.cpp:429-460). Without the
fsyncs a crash can leave the renamed file empty or revert the rename, and this
is now rewritten on EVERY start, so it is the crash window an operator hits
most often. A truncated settings file refuses the next start outright.

The wallet layer is the other writer: it reads the whole object and replaces
only the \"wallet\" key, and this reader keeps every key it did not put there,
so the two compose rather than clobbering each other."
  (handler-case
      (let ((tmp (make-pathname :type "json.tmp" :defaults path)))
        (ensure-directories-exist path)
        (with-open-file (out tmp :direction :output :external-format :utf-8
                                 :if-exists :supersede :if-does-not-exist :create)
          (write-string (bl:render-settings-json alist) out))
        (bl.store::fsync-file tmp)
        (rename-file tmp path)
        (bl.store::fsync-directory path))
    (error (e)
      (error "Settings file could not be written: ~A" e))))

(defun %log-args (args conf-texts settings-cells network)
  "Core's LogArgs(): every option that actually took effect, tagged with where
it came from and rendered as the JSON value that was stored.

Only KNOWN options are logged for the config file and the command line — Core
skips anything GetArgFlags does not recognise (args.cpp:880-884) — while EVERY
settings-file entry is logged, known or not."
  (dolist (text conf-texts)
    (dolist (cell (bl::%config-arg-log-cells text network))
      (destructuring-bind (section name json) cell
        (when (known-config-option-p name)
          (defer-log :info "Config file arg: ~:[~;[~:*~A] ~]~A=~A"
                     (and (plusp (length section)) section) name json)))))
  (dolist (cell settings-cells)
    (defer-log :info "Setting file arg: ~A = ~A"
               (car cell) (bl:render-json-value (cdr cell))))
  (dolist (cell (bl::%cli-arg-log-cells args))
    (when (known-config-option-p (car cell))
      (defer-log :info "Command-line arg: ~A=~A" (car cell) (cdr cell)))))

(defun start-node-from-args (&optional (args (rest sb-ext:*posix-argv*)))
  "Start the node from Bitcoin Core-style options: a list of CLI ARGS
 (-key=value, -key, -nokey) plus a bitcoin.conf read from the data directory.
CLI arguments override the config file. This is the argv-friendly entry point —
 e.g. from a saved image's toplevel, or (start-node-from-args
'(\"-chain=main\" \"-txindex\" \"-dbcache=2000\" \"-server\")).

The data directory and network are resolved from the CLI first (so the config
file can be located and its [network] section scoped), then the merged config
is turned into start-node keyword arguments. -conf=PATH overrides the config
file location."
  ;; Unknown command-line options are a HARD startup error, exactly like
  ;; Core ArgsManager::ParseParameters ("Invalid parameter -foo").
  (check-cli-args args)
  (let* ((cli (parse-cli-args args))
         ;; Normalized to end in a separator, and kept a STRING because the
         ;; config layer treats it as one. Core accepts -datadir with or
         ;; without a trailing separator; without this, "/tmp/x" parses as a
         ;; FILE pathname named "x" and every merge against it moves the
         ;; datadir (/tmp/regtest/chainstate/x).
         (datadir (namestring
                   (uiop:ensure-directory-pathname
                    (or (cdr (assoc "datadir" cli :test #'string=))
                        "~/.bitcoin-lisp/"))))
         (conf-path (or (cdr (assoc "conf" cli :test #'string=))
                        ;; Ensure a trailing slash so DATADIR is treated as a
                        ;; directory (else merge-pathnames replaces its last
                        ;; component).
                        (merge-pathnames
                         "bitcoin.conf"
                         (pathname (if (and (plusp (length datadir))
                                            (char= (char datadir (1- (length datadir))) #\/))
                                       datadir
                                       (concatenate 'string datadir "/"))))))
         (conf-text (progn
                      (%check-datadir-option cli)
                      (when (probe-file conf-path)
                        (defer-log :info "Reading config file ~A" conf-path)
                        (alexandria:read-file-into-string conf-path))))
         (conf-texts (%read-config-includes conf-text cli datadir))
         ;; The settings file lives inside the NETWORK directory, so the
         ;; network has to be resolved first — from the command line and the
         ;; config file's global area only, which is where Core reads its chain
         ;; selectors (args.cpp:825-829). Resolving it from the merged config
         ;; instead would let settings.json choose the directory it is read
         ;; from.
         (conf-globals (loop for text in conf-texts
                             append (conf-global-entries text)))
         (settings-network (resolve-network-from-config (append cli conf-globals)))
         ;; CLI, then the [network] section, then the global area — the same
         ;; order ARGS->START-NODE-PLIST uses, minus the settings file itself.
         (settings-scope
           (append cli
                   (loop for text in conf-texts
                         append (parse-bitcoin-conf-sections text settings-network))
                   conf-globals))
         (settings-path (%settings-file-path settings-scope datadir settings-network))
         (settings-cells (and settings-path (%read-settings-file settings-path))))
    (multiple-value-bind (plist merged)
        (args->start-node-plist args conf-texts
                                (bl:settings-alist->config-alist
                                 settings-cells))
      ;; Unknown CONFIG-FILE keys only warn (Core ReadConfigFiles with
      ;; ignore_invalid_keys=true, common/init.cpp:38: "Ignoring unknown
      ;; configuration value") — unlike unknown CLI options, which error.
      ;; Every file that was read, not just the main one — an unknown key in an
      ;; included file is exactly as worth reporting.
      (dolist (k (unknown-config-file-keys
                  (loop for text in conf-texts append (parse-bitcoin-conf text))))
        (defer-log :warn "Ignoring unknown configuration value ~A" k))
      ;; Options bitcoind accepts that this node does not implement. They are
      ;; accepted so an ordinary Core command line starts us at all, but every
      ;; one that was actually SUPPLIED is named here — an operator who passes
      ;; -asmap or -whitelist must not be left believing it took effect.
      (let ((ignored (supplied-core-only-options merged)))
        (when ignored
          (defer-log :warn "Accepted but NOT implemented by this node, so ~
~:[this option has~;these options have~] no effect: ~{-~A~^ ~}"
                     (rest ignored) ignored)))
      ;; Core's LogArgs(), in Core's order: config file, then settings file,
      ;; then command line (args.cpp:889-900). The functional tests read these
      ;; back to check how an option was actually resolved, so both the wording
      ;; and the JSON rendering of the value are part of the contract.
      (%log-args args conf-texts settings-cells settings-network)
      ;; BEFORE the settings file is written, because writing it creates the
      ;; network directory and %ENSURE-WALLETS-SUBDIRECTORY only acts on a
      ;; directory that does not exist yet. START-NODE calls it too, for callers
      ;; that come in that way (scripts/run-node.sh does); the call is
      ;; idempotent, and whichever runs first is the one that decides.
      (%ensure-wallets-subdirectory datadir settings-network)
      ;; Rewriting it on every start is what makes a datadir that has ever been
      ;; started always have one, which is what Core does (common/init.cpp:111)
      ;; and what feature_settings.py asserts.
      (when settings-path
        (%write-settings-file settings-path settings-cells))
      ;; Apply the process-global config specials (options with no start-node
      ;; keyword) from the same merged config, before launching.
      (apply-config-globals merged)
      ;; The RPC half, which config.lisp cannot express (see
      ;; APPLY-RPC-CONFIG-GLOBALS).
      (apply-rpc-config-globals merged)
      ;; datadir only comes from the CLI/default (locating the conf needs it), so
      ;; make sure it reaches start-node even if it wasn't in the spec scan.
      (unless (getf plist :data-directory)
        (setf (getf plist :data-directory) datadir))
      (setf (getf plist :data-directory)
            (%normalize-datadir (getf plist :data-directory)))
      (apply #'start-node plist))))

;;;; The saved executable's entry point
;;;;
;;;; Core's functional test framework launches a NODE, not a Lisp: it spawns
;;;; `$BITCOIND -datadir=... -regtest ...`, waits for the RPC to answer, and at
;;;; every stop asserts the exit code AND that stderr is EMPTY
;;;; (test_node.py:497-509). That shape is what NODE-MAIN provides.

(defun %argv-option-name (arg)
  "The option name in ARG (\"-foo=1\" -> \"foo\"), or NIL when ARG is not an
option. Leading dashes and the value are stripped, as Core's ArgsManager does."
  (when (and (stringp arg) (plusp (length arg)) (char= (char arg 0) #\-))
    (let* ((s (string-left-trim "-" arg))
           (eq-pos (position #\= s)))
      (string-downcase (if eq-pos (subseq s 0 eq-pos) s)))))

(defun %argv-asks-for (args names)
  "T when any of ARGS names one of NAMES."
  (loop for arg in args
        for name = (%argv-option-name arg)
        thereis (and name (member name names :test #'string=))))

(defun node-main ()
  "Toplevel of the saved executable: run a node from the command line and exit
with the code the caller should act on.

Exit codes are RUN-NODE-WATCHDOG's, which the supervisor already discriminates
on: 0 for a deliberate completed stop, 1 for a deterministic failure, 7 for a
node that died unasked.

Nothing is written to stderr on a normal run. Core's test framework reads
stderr back at EVERY node stop and fails the test unless it is exactly empty
(test_node.py:502-509), so a stray warning there is not cosmetic — it breaks
every test that stops a node. Startup FAILURES do go to stderr, which is also
Core's behaviour and what assert_start_raises_init_error reads."
  (sb-ext:disable-debugger)
  (let ((args (rest sb-ext:*posix-argv*)))
    (handler-case
        (cond
          ;; -version and -help print and exit 0 before anything is started,
          ;; as they do in Core (init.cpp's HelpRequested/-version branch).
          ((%argv-asks-for args '("version"))
           (format t "bitcoin-lisp version ~A~%"
                   (bl.ser:client-version-string))
           (finish-output)
           (sb-ext:exit :code 0))
          ((%argv-asks-for args '("help" "h" "?"))
           (format t "bitcoin-lisp version ~A~%~%~
Usage: bitcoin-lisp-node [options]~%~%~
Runs a Bitcoin full node. Options follow Bitcoin Core's spelling ~
(-datadir, -regtest, -rpcport, ...); see docs/ for what is implemented, and ~
note that options this node accepts but does not implement are reported at ~
startup.~%"
                   (bl.ser:client-version-string))
           (finish-output)
           (sb-ext:exit :code 0))
          (t
           (start-node-from-args args)
           ;; Blocks until shutdown, runs stop-node on THIS thread so the
           ;; flush/mempool.dat/peers.dat sequence completes, then exits.
           (run-node-watchdog)
           ;; run-node-watchdog exits by itself; reaching here means it was
           ;; told not to, so report a clean stop.
           (sb-ext:exit :code 0)))
      (error (e)
        ;; A startup failure is what Core prints to stderr and exits 1 for.
        (ignore-errors
         (format *error-output* "Error: ~A~%" e)
         (finish-output *error-output*))
        (sb-ext:exit :code 1 :abort t)))))

(defparameter +flush-every-n-blocks+ 25000
  "Block-count flush backstop. The 600s time trigger and the 450MiB
   coins-cache size trigger are the real guards; this count only caps the
   redo window if both somehow fail to fire. Was 1000, which at mainnet
   IBD speed (~30 b/s) meant a full header-index rewrite + CRC every
   ~35s — ~6% of CPU by sb-sprof at h≈280k. A crash now redoes at most
   ~10 min of validation (the time trigger), like Core's
   DATABASE_WRITE_INTERVAL bounding work by time, not block count.")

(defparameter +flush-every-n-seconds+ 600
  "Time-based flush trigger (10 min): flush if at least N seconds have
   elapsed since the last flush, regardless of block count. Without this,
   a slow sync window (~2 b/s on testnet4 stress regions) takes ~8 min
   to accumulate 1000 blocks, and a connect-tip stall halts flushes
   entirely (May 2 crash: stuck at h=70700 for 1h40m, last save was at
   h=70000 at 14:34, lost 700 blocks of progress + caused full re-sync
   from genesis on restart). Bitcoin Core uses DATABASE_WRITE_INTERVAL
   = 1h (validation.cpp:DATABASE_WRITE_INTERVAL) — we use 10 min because
   our re-validation from a checkpoint is much slower than Core's.")

(defvar *coins-cache-budget-bytes* (* 450 1024 1024)
  "Memory budget for the in-memory UTXO (coins) cache before a size-triggered
flush. Default mirrors Bitcoin Core's DEFAULT_DB_CACHE (kernel/caches.h,
450 MiB); start-node's :dbcache-mib raises it (Core's -dbcache). A larger
budget keeps more of the UTXO set in RAM, cutting LevelDB disk reads during
IBD — the dominant cost once the chainstate outgrows the LevelDB table cache
(profiled I/O-wait-bound at mainnet h~828k). The cache flushes-and-clears at
the LARGE threshold, so memory stays bounded (the unbounded cache was the
original mainnet OOM blocker).")

(defun large-coins-cache-threshold (budget)
  "The coins-cache usage at which a periodic flush is due. Mirrors Bitcoin Core's
LargeCoinsCacheThreshold (validation.h): flush once less than 10 MiB (or 10% of
the budget, whichever is larger free margin) remains."
  (max (floor (* budget 9) 10)
       (- budget (* 10 1024 1024))))

(defun maybe-critical-flush (chainstate)
  "Flush CHAINSTATE only when its coins cache has exceeded its whole budget —
Core's CRITICAL tier (validation.cpp:2690), the one FlushStateMode::IF_NEEDED
acts on (:2763).

This exists for the reorg loops. Core calls FlushStateToDisk(IF_NEEDED) at the
end of BOTH DisconnectTip (validation.cpp:2966) and ConnectTip (:3093), so the
cache is size-checked once per disconnected AND per connected block, including
mid-reorg. We had exactly one flush call site in the whole tree — the
tip-extension path of connect-block — so perform-reorg ran its disconnect and
connect loops with nothing draining the cache at all. Every disconnected block
restores its spent prevouts as dirty entries and every connected fork block
adds its outputs; a deep rollback (dumptxoutset to an assumeutxo height, or
invalidateblock on an old hash) walks tens of thousands of blocks in one
uninterrupted loop. This heap has already been OOM-killed twice on this cache.

CRITICAL rather than the LARGE threshold MAYBE-PERIODIC-FLUSH uses, and
deliberately NOT that function: its count and time triggers would fire
repeatedly inside a deep reorg and turn a rollback into a flush storm. Core
draws the same distinction — PERIODIC acts on LARGE, IF_NEEDED only on
CRITICAL.

MUST be called where the coins-view best-block pointer already names the block
whose coins are in the cache, i.e. AFTER the apply/disconnect call rather than
between the mutation and the pointer move. Both COIN-VIEW-APPLY-BLOCK and
DISCONNECT-BLOCK-FROM-UTXO-SET set that pointer as their last act, so calling
this immediately after either is safe; anywhere else would persist a cache and
a pointer that disagree."
  (when *node*
    (let ((view (and chainstate
                     (bl.store:chain-state-coins-view chainstate))))
      (when (and view
                 (>= (bl.store:view-mem-bytes view)
                     (chainstate-coins-cache-budget chainstate)))
        (log-info "Coins cache past its budget mid-reorg; flushing")
        (log-memory-snapshot "pre-flush-critical")
        (%flush-chainstate chainstate)
        (setf *blocks-since-flush* 0
              *last-flush-universal-time* (bl.ser:get-node-time))
        t))))

(defun chainstate-coins-cache-budget (chainstate)
  "CHAINSTATE's coins-cache budget in bytes: its per-chainstate allocation
when maybe-rebalance-caches has split the global budget (assumeutxo dual
chainstates), otherwise the whole *coins-cache-budget-bytes*."
  (or (bl.store:chain-state-coins-cache-bytes chainstate)
      *coins-cache-budget-bytes*))

(defun maybe-rebalance-caches (node)
  "Split the coins-cache budget between NODE's chainstates (Core
ChainstateManager::MaybeRebalanceCaches, validation.cpp:6103-6134). A sole
chainstate gets everything — both the ordinary no-snapshot case and the
snapshot chainstate after background validation completes. While BOTH
chainstates exist, the one doing the urgent work gets 95%: the snapshot
(current) chainstate while the node is still in IBD, the historical
chainstate once the tip is synced. Core calls this at chainstate init,
snapshot activation (incl. the activation-failure cleanup), background-
validation completion, and on IBD exit; our call sites mirror those.

Divergence from Core: Core sizes TWO caches per chainstate (coinstip +
coinsdb) from separate totals; we keep one coins cache per chainstate whose
budget is a flush-trigger threshold (maybe-periodic-flush), so the same
ratios apply to the single global budget and take effect at the next flush
check rather than through an immediate resize/eviction."
  (let ((current (node-current-chainstate node))
        (historical (node-historical-chainstate node)))
    (cond
      ((null historical)
       (when (and current
                  (bl.store:chain-state-from-snapshot-blockhash current))
         (log-info "[snapshot] allocating all cache to the snapshot chainstate"))
       (when current
         (setf (bl.store:chain-state-coins-cache-bytes current) nil)))
      (t
       (let ((total *coins-cache-budget-bytes*))
         (multiple-value-bind (current-share historical-share)
             (if (bl.net:initial-block-download-p current)
                 (values 0.95d0 0.05d0)
                 (values 0.05d0 0.95d0))
           (setf (bl.store:chain-state-coins-cache-bytes current)
                 (floor (* total current-share))
                 (bl.store:chain-state-coins-cache-bytes historical)
                 (floor (* total historical-share)))
           (log-info "[snapshot] coins-cache budgets rebalanced: current chainstate ~D MiB, historical chainstate ~D MiB"
                     (floor (chainstate-coins-cache-budget current) 1048576)
                     (floor (chainstate-coins-cache-budget historical) 1048576))))))))

(defun rebalance-caches-on-ibd-exit ()
  "Rebalance the coins-cache allocation when the node leaves initial block
download while a background (historical) chainstate is in use (Core
ActivateBestChain's exited_ibd hook, validation.cpp:3479-3486). Called from
the IBD latch flip in bl.net:initial-block-download-p."
  (let ((node *node*))
    (when (and node (node-historical-chainstate node))
      (maybe-rebalance-caches node))))

(defun effective-prune-target-bytes ()
  "The automatic-prune target in bytes (Core BlockManager::FindFilesToPrune,
node/blockstorage.cpp:330-338): the -prune target divided by the number of
chainstates — halved while an assumeutxo historical chainstate exists, so
half the block storage is reserved for the historical chainstate's
re-derivation and the other half for the most-work chainstate — and floored
at +min-disk-space-for-block-files+ (550 MiB, validation.h:87)."
  (let ((num-chainstates (if (and *node* (node-historical-chainstate *node*)) 2 1)))
    (max +min-disk-space-for-block-files+
         (floor (* *prune-target-mib* 1048576) num-chainstates))))

(defvar *blocks-since-flush* 0
  "Counter incremented per connected block; reset to 0 when a flush runs.")

(defvar *last-flush-universal-time* 0
  "Node-clock time (GET-NODE-TIME) of the last successful periodic flush. Used
   by the time-based trigger.

   Mockable on purpose: Core reads NodeClock::now() for the PERIODIC flush
   decision (validation.cpp:2759,2765) and SteadyClock only for the durations
   it logs (:2301,2382).")

(defun log-memory-snapshot (label)
  "Log a snapshot of the major in-memory caches plus SBCL heap usage.
Used to diagnose memory growth — call before/after flush so we can
correlate cache sizes with the heap watermark.

The May 5 OOM at h=72814 had heap at 8.55 GB but the explainable
state (UTXO 600MB + headers 30MB + sig-cache 5MB + queues 80MB) only
accounts for ~700 MB. This logger surfaces the gap."
  #+sbcl
  (let* ((utxo-count (and (node-utxo-set *node*)
                          (bl.store:utxo-count
                           (node-utxo-set *node*))))
         (coins-cache-mb (and (node-utxo-set *node*)
                              (/ (bl.store:view-mem-bytes
                                  (node-utxo-set *node*))
                                 1048576.0)))
         (header-count (and (node-chain-state *node*)
                            (hash-table-count
                             (bl.store::chain-state-block-index
                              (node-chain-state *node*)))))
         (sig-cache-count
           (+ (hash-table-count bl.interop:*signature-cache*)
              (hash-table-count bl.interop:*signature-cache-prev*)))
         (ibd-pending
           (and bl.net::*ibd-context*
                (hash-table-count
                 (bl.net::ibd-context-pending-blocks
                  bl.net::*ibd-context*))))
         (ibd-queue
           (and bl.net::*ibd-context*
                (hash-table-count
                 (bl.net::ibd-context-block-queue
                  bl.net::*ibd-context*))))
         (ibd-in-flight
           (and bl.net::*ibd-context*
                (hash-table-count
                 (bl.net::ibd-context-in-flight
                  bl.net::*ibd-context*))))
         (dyn-bytes (sb-ext:dynamic-space-size))
         (used-bytes (sb-kernel:dynamic-usage)))
    (log-info "MEM[~A]: utxo=~D coins-cache=~,1FMB headers=~D sigcache=~D ibd-pend=~A queue=~A inflight=~A heap-used=~,1FMB heap-cap=~,1FMB"
              label utxo-count coins-cache-mb header-count sig-cache-count
              ibd-pending ibd-queue ibd-in-flight
              (/ used-bytes 1048576.0) (/ dyn-bytes 1048576.0))))

(defvar *flush-mid-commit-hook* nil
  "When non-NIL, funcalled with the chainstate between Phase 1 (in-transition
marker written) and Phase 2 (coins flush) of %flush-chainstate — inside the
window where a crash must be detected at the next startup. Production leaves
it NIL; crash-safety tests bind it to observe the on-disk marker or abort
(via THROW) to simulate a crash at the most dangerous point.")

(defun %flush-chainstate (chainstate &key (label "Periodic") force-full-header-index)
  "Synchronously flush one CHAINSTATE (its state file, its coins view, and
the shared header index) with 3-phase commit (mirrors Bitcoin Core's
DB_HEAD_BLOCKS marker pattern in txdb.cpp::CCoinsViewDB::BatchWrite).
Each chainstate flushes its own storage-suffix-named files, so flushing one
can never mark another's state file in-transition. Per-flush-CYCLE concerns
(trigger counter resets, the post-flush GC, memory snapshots) live in the
callers — this is strictly the per-chainstate mechanism. LABEL names the
flush in log lines (\"Periodic\", \"Shutdown\", \"Reindex\").

  Phase 1: save-state with in-transition=1 — chainstate.dat marked unsafe.
           If we crash anywhere from here through Phase 3, on restart
           load-state returns :inconsistent and the caller refuses to
           start (must re-sync).
  Phase 2: save-utxo-set — the slow 90-MB write. Uses temp + fsync +
           rename internally so the file itself is atomic, but it might
           be old-or-new depending on whether the rename completed.
  Phase 3: save-state with in-transition=0 — commits the new chainstate.

The previous non-atomic flush ordered chainstate-then-utxo. If
interrupted between, on-disk best-height was ahead of the saved UTXO
entries, which then cascaded into MISSING-INPUT validation failures on
restart (observed at testnet4 h=70541 — block 70514 tx-2's outputs
were nowhere in utxoset.dat despite chainstate showing h=70540)."
  ;; Free-disk-space gate (Core FlushStateToDisk's CheckDiskSpace calls,
  ;; validation.cpp:2775/2808): refuse to start a flush the disk cannot
  ;; absorb, and request shutdown like Core's FatalError.
  (when (and chainstate *node* (node-data-directory *node*)
             (not (check-disk-space (node-data-directory *node*))))
    (%abort-on-low-disk-space label)
    (return-from %flush-chainstate nil))
  (handler-case
      (#+sbcl sb-sys:without-interrupts
       #-sbcl progn
        ;; Phase 1: mark the chainstate as in-transition.
        (when chainstate
          (bl.store:save-state chainstate :in-transition t)
          ;; A shutdown writes the FULL header index rather than a delta: it
          ;; is the one moment we can guarantee the on-disk snapshot matches
          ;; memory exactly, which bounds any drift the packed change-detector
          ;; could not see (a replaced header object on an existing entry).
          (bl.store:save-header-index
           chainstate :force-full force-full-header-index))
        (when *flush-mid-commit-hook*
          (funcall *flush-mid-commit-hook* chainstate))
        ;; Phase 2: flush cache → LevelDB. Per-flush work is proportional
        ;; to dirty entries (typically a few thousand at the tip), not
        ;; the full ~17M-entry set — replaces the ~13s utxoset.dat
        ;; rewrite that previously froze the sync thread.
        (let ((view (and chainstate
                         (bl.store:chain-state-coins-view chainstate))))
          (when (typep view 'bl.store:coins-view-cache)
            ;; :sync t fdatasyncs the LevelDB writebatch before we proceed, so a
            ;; power loss after Phase 3 clears the marker cannot leave the coins
            ;; un-durable while chainstate.dat says they are committed. (Was
            ;; :sync nil — atomic but not durable; the shutdown flush already
            ;; syncs, the periodic one now matches it.)
            ;; The coins DB is stamped with the block THESE COINS correspond to,
            ;; inside the same batch. The cache tracks that itself (moved by
            ;; block apply/disconnect, as Core does in Connect/DisconnectBlock),
            ;; so we deliberately do NOT pass the chain's tip here: during a
            ;; reorg's disconnect phase the tip still names the block being
            ;; rewound away from, and stamping it would record a hash the coins
            ;; no longer match. chainstate.dat (Phase 3 below) remains a second
            ;; record of the tip; startup compares the two.
            (bl.store:coins-view-cache-flush view :sync t)))
        ;; Phase 3: commit by re-saving chainstate without the marker.
        (when chainstate
          (bl.store:save-state chainstate :in-transition nil))
        (log-info "~A flush: chainstate~@[~A~] at height ~D"
                  label
                  (let ((suffix (and chainstate
                                     (bl.store:chain-state-storage-suffix
                                      chainstate))))
                    (and suffix (plusp (length suffix)) suffix))
                  (and chainstate
                       (bl.store:current-height chainstate))))
    (error (c)
      ;; Was log-warn before — surfaced silently. Bumped to log-error so
      ;; persistence failures are obvious in the log instead of getting
      ;; lost between progress lines.
      (log-error "~A flush FAILED: ~A" label c)
      ;; And now FATAL, as it is in Core: FlushStateToDisk wraps its writes in
      ;; a try/catch whose handler is `AbortNode(state, ...)`
      ;; (validation.cpp:2698, 2775-2777), because a node that keeps connecting
      ;; blocks after a failed flush is advancing a chain whose coins are not
      ;; on disk — and the loss is only discovered by the NEXT crash, as a
      ;; chainstate ahead of its UTXO entries. That exact cascade is what
      ;; testnet4 h=70541 was; logging it and carrying on is how it stayed
      ;; invisible until restart.
      (%abort-on-flush-failure label c)
      nil)))

(defun do-flush (&optional (chainstate (and *node* (node-current-chainstate *node*))))
  "Flush CHAINSTATE (default: the node's current chainstate) and run the
per-cycle bookkeeping: reset the periodic-flush triggers, request a major GC
so reachable post-flush memory is the only thing in the old generations next
time we measure (the same pattern as Bitcoin Core's CCoinsViewCache::Flush
returning bytes freed to the system allocator), and log memory snapshots."
  (log-memory-snapshot "pre-flush")
  (%flush-chainstate chainstate)
  (setf *last-flush-universal-time* (bl.ser:get-node-time)
        *blocks-since-flush* 0)
  #+sbcl (sb-ext:gc :full t)
  (log-memory-snapshot "post-flush"))

(defun maybe-periodic-flush (&optional chainstate)
  "Flush chainstates (state file, coins view, and the header index) to disk
if either:
- N blocks have been connected since the last flush, OR
- N seconds have elapsed since the last flush (catches slow-sync regions
  where 1000 blocks would take many minutes to accumulate).

Called from connect-block, which passes the chainstate the block connected
to; defaults to the node's current chainstate. The size trigger checks the
connecting chainstate's own coins cache; once ANY trigger fires, EVERY
chainstate is flushed — with an assumeutxo background sync two chainstates
connect blocks concurrently but the global time/count triggers reset on any
flush, so flushing only the triggering one would let the other's dirty
coins and redo window grow unboundedly. Flushing a clean chainstate is
cheap (work is proportional to dirty entries). Cheap if no flush needed;
durable if it does flush (atomic temp+fsync+rename inside save-*)."
  (unless *node* (return-from maybe-periodic-flush))
  (let* ((cs (or chainstate (node-current-chainstate *node*)))
         (view (and cs (bl.store:chain-state-coins-view cs))))
    (incf *blocks-since-flush*)
    (when (zerop *last-flush-universal-time*)
      (setf *last-flush-universal-time* (bl.ser:get-node-time)))
    (when (or (>= *blocks-since-flush* +flush-every-n-blocks+)
              (>= (- (bl.ser:get-node-time) *last-flush-universal-time*)
                  +flush-every-n-seconds+)
              ;; Size trigger (Bitcoin Core dbcache): flush once the coins cache
              ;; reaches its memory budget, so it can't grow unbounded between the
              ;; block-count / time flushes. The budget is per-chainstate while an
              ;; assumeutxo background sync splits it (maybe-rebalance-caches).
              (and view
                   (>= (bl.store:view-mem-bytes view)
                       (large-coins-cache-threshold
                        (chainstate-coins-cache-budget cs)))))
      ;; Triggering chainstate first (its cache may be the urgent one),
      ;; then the rest. Per-cycle bookkeeping (trigger resets, ONE major
      ;; GC, memory snapshots) runs once around the whole pass — not per
      ;; chainstate, which would double the stop-the-world GC pauses
      ;; during an assumeutxo background sync.
      (log-memory-snapshot "pre-flush")
      (%flush-chainstate cs)
      (dolist (other (node-chainstates *node*))
        (unless (eq other cs)
          (%flush-chainstate other)))
      (setf *last-flush-universal-time* (bl.ser:get-node-time)
            *blocks-since-flush* 0)
      #+sbcl (sb-ext:gc :full t)
      (log-memory-snapshot "post-flush"))))

(defvar *index-stall-logged* '()
  "Names of indexes whose non-contiguous refusal has been logged: once per
index per process, not once per block.")

(defun node-indexes (node)
  "NODE's enabled indexes -- transaction, block filter, coinstats and spender
-- in the order they are driven. Every connect, disconnect and catch-up
reaches them through this list, so no call site can switch one off by
forgetting an argument (the shape of the 3rd, 6th, 7th and 15th no-caller
bugs, all of them the txindex)."
  (remove-if-not #'bl.store:base-index-enabled
                 (remove nil (list (node-tx-index node)
                                   (node-blockfilterindex node)
                                   (node-coinstatsindex node)
                                   (node-txospenderindex node)))))

(defun index-block-connected (chainstate block block-hash height spent-utxos)
  "Connect-time hook (Core BaseIndex::BlockConnected): fold BLOCK, connected
at HEIGHT with SPENT-UTXOS as its undo list, into every enabled index.
CHAINSTATE is the chainstate the block connected to; signals from any
chainstate other than the node's VALIDATED one are dropped -- indexes index
blocks in order from genesis, so they bind Core's ValidatedChainstate
(init.cpp:1367-1383) and must ignore an unvalidated snapshot chainstate's
tip-range connects. Never signals: an index failure must not abort a block
connect, so consensus is unaffected whether an index is on or off."
  (when (and *node* (eq chainstate (node-validated-chainstate *node*)))
    (dolist (index (node-indexes *node*))
      (let ((name (bl.store:index-name index)))
        (handler-case
            (multiple-value-bind (result status)
                (bl.store:index-write-block index chainstate block block-hash height spent-utxos)
              (declare (ignore result))
              (when (and (eq status :noncontiguous)
                         (not (member name *index-stall-logged* :test #'string=)))
                (push name *index-stall-logged*)
                (log-warn "~A stalled at height ~D: gap below best-indexed height ~D; ~
the startup backfill will heal it on next restart"
                          name height (bl.store:index-height index chainstate))))
          (error (e)
            (log-warn "~A failed at height ~D: ~A" name height e)))))))

(defun index-block-disconnected (chainstate block block-hash height)
  "Disconnect-time hook (Core BaseIndex's rewind): erase what
INDEX-BLOCK-CONNECTED wrote for BLOCK (at HEIGHT) in every enabled index.
Same chainstate rule and same never-signals rule as the connect hook."
  (when (and *node* (eq chainstate (node-validated-chainstate *node*)))
    (dolist (index (node-indexes *node*))
      (handler-case
          (bl.store:index-rewind-block index chainstate block block-hash height)
        (error (e)
          (log-warn "~A failed to rewind ~A: ~A"
                    (bl.store:index-name index) (bl.crypto:bytes-to-hex block-hash) e))))))

(defmethod bl.store:index-write-block ((csi bl.store:coinstatsindex) chainstate block block-hash height spent-utxos)
  "The coinstats fold needs the block subsidy, which is consensus; that is
why this method lives here rather than in storage."
  (declare (ignore chainstate))
  (values (bl.store:coinstatsindex-add-block csi block block-hash height spent-utxos
                                             (bl.val:calculate-block-subsidy height))
          nil))

(defun do-reindex-chainstate ()
  "Rebuild the UTXO set from already-stored blocks (Bitcoin Core
-reindex-chainstate): wipe the coins view, reset the chainstate to genesis,
and re-apply every stored active-chain block's UTXO effects, trusting the
already-validated stored blocks (no script re-validation, no re-download).
The undo files are left as-is -- they record spent prevouts, which the rebuild
does not change. Clears the coinstatsindex best marker so its startup backfill
rebuilds it against the reindexed set; the blockfilterindex is unaffected
(its filters are over block scripts, not the UTXO set).

This realizes UTXO-set-content changes (e.g. dropping now-skipped unspendable
outputs) on an existing node without a full network resync, and doubles as
chainstate disaster-recovery when blocks+index are intact but the coins DB is
suspect.

Crash safety: before the wipe, chainstate.dat is rewound to genesis WITH the
in-transition marker, and every flush during the replay (size-triggered and
final) goes through the 3-phase %flush-chainstate. In Core the coins DB owns
its own tip (DB_BEST_BLOCK is erased by the -reindex-chainstate wipe and
re-committed atomically with the coins in each BatchWrite, txdb.cpp:124-159),
so a crashed rebuild can never load a tip ahead of the coins; our separate
chainstate.dat needs the marker discipline to get the same guarantee. A crash
before the first replay flush completes leaves tip=genesis + marker, which
recover-inconsistent-chainstate resolves by re-wiping (nothing should be
committed at genesis; anything on disk is refuse from the interrupted wipe).
A crash later leaves the marker at the current replay height with the coins
DB at exactly the last committed flush height, so the standard walk-back
recovery rewinds chainstate.dat to it. Previously the old CLEAN pre-reindex
chainstate.dat sat untouched over the gutted coins DB for the whole replay —
a crash loaded it silently over garbage."
  (let* ((cs (node-chain-state *node*))
         (store (node-block-store *node*))
         (utxo (node-utxo-set *node*))
         (tip-hash (bl.store:best-block-hash cs))
         (tip-entry (and tip-hash (bl.store:get-block-index-entry cs tip-hash)))
         (tip-height (bl.store:current-height cs)))
    (when (or (null tip-entry) (zerop tip-height))
      (log-info "Reindex-chainstate: empty chain, nothing to rebuild")
      (return-from do-reindex-chainstate))
    (log-info "Reindex-chainstate: rebuilding UTXO set from ~D stored blocks..." tip-height)
    ;; Active chain genesis+1 .. tip, ascending (push while walking prev-entry
    ;; down from the tip leaves the list in height order).
    (let ((entries '()))
      (loop with e = tip-entry
            while (and e (plusp (bl.store:block-index-entry-height e)))
            do (push e entries)
               (setf e (bl.store:block-index-entry-prev-entry e)))
      ;; Rewind the chainstate to genesis and persist it WITH the
      ;; in-transition marker BEFORE touching the coins DB: from here until
      ;; the first replay flush commits, a crash is detected at load-state
      ;; and resolved by recover-inconsistent-chainstate's genesis branch
      ;; (re-wipe + clear), never loaded as clean state over a gutted set.
      (bl.store:update-chain-tip
       cs (bl.store::chain-state-genesis-hash cs) 0)
      (bl.store:save-state cs :in-transition t)
      ;; Empty the coins view.
      (let ((erased (bl.store:coins-view-cache-wipe utxo)))
        (log-info "Reindex-chainstate: erased ~D coin~:P; replaying..." erased))
      ;; NB: the coinstatsindex is opened AFTER this runs; its rebuild is
      ;; forced in its own init block (keyed off the reindex flag), not here.
      ;; The blockfilterindex is left alone -- its filters are over block
      ;; scripts, unaffected by a UTXO-set rebuild.
      ;; Replay every block's UTXO effects.
      (let ((n 0) (last-report (get-internal-real-time)))
        (block replay
          (dolist (entry entries)
            (let* ((hash (bl.store:block-index-entry-hash entry))
                   (height (bl.store:block-index-entry-height entry))
                   (blk (bl.store:get-block store hash)))
              (unless blk
                (log-warn "Reindex-chainstate: block at height ~D missing from store; ~
stopping (UTXO set rebuilt to height ~D)" height (1- height))
                (return-from replay))
              ;; Apply removes spent prevouts + adds spendable outputs (the
              ;; unspendable skip lives in apply-block-to-utxo-set). Discard the
              ;; returned undo list -- the on-disk undo files are unchanged.
              (bl.store:apply-block-to-utxo-set utxo blk height)
              (bl.store:update-chain-tip cs hash height)
              (incf n)
              ;; Size-triggered flushes go through the 3-phase commit like
              ;; the periodic flush: marker at the replay height, one atomic
              ;; synced coins batch, marker cleared — so the on-disk pair is
              ;; always chainstate.dat <= coins DB by an identifiable gap.
              (when (>= (bl.store:view-mem-bytes utxo)
                        (large-coins-cache-threshold *coins-cache-budget-bytes*))
                (%flush-chainstate cs :label "Reindex"))
              (let ((now (get-internal-real-time)))
                (when (> (- now last-report) internal-time-units-per-second)
                  (log-info "Reindex-chainstate: height ~D (~,1F%)"
                            height (* 100.0 (/ height tip-height)))
                  (setf last-report now))))))
        (%flush-chainstate cs :label "Reindex")
        (log-info "Reindex-chainstate complete: ~D block~:P re-applied, tip at height ~D"
                  n (bl.store:current-height cs))))))

(defun force-compact-databases ()
  "Full-compact every LevelDB the node has open -- the coins/chainstate DB plus
the block-filter and coinstats indexes -- reclaiming the disk that tombstones
still pin after a large deletion churn (e.g. a reindex-chainstate wipe). Mirrors
Bitcoin Core's -forcecompactdb, which sets CDBWrapper force_compact on each
database it opens. Synchronous and potentially slow on a large chainstate."
  (flet ((compact (label db)
           (when db
             (log-info "Starting database compaction of ~A" label)
             (bl.store:leveldb-compact db)
             (log-info "Finished database compaction of ~A" label))))
    (let ((utxo (node-utxo-set *node*))
          (bfi (node-blockfilterindex *node*))
          (csi (node-coinstatsindex *node*)))
      (when utxo
        (log-info "Starting database compaction of chainstate")
        (bl.store:coins-view-cache-compact utxo)
        (log-info "Finished database compaction of chainstate"))
      (when bfi (compact "blockfilterindex" (bl.store:blockfilterindex-db bfi)))
      (when csi (compact "coinstatsindex" (bl.store:coinstatsindex-db csi))))))

;;; Wallet chain-tracking hooks (wallet P2). Hardcoded call sites like the
;;; index hooks above: connect-block / perform-reorg call the block pair,
;;; mempool-add / mempool-remove call the mempool pair. Each is a cheap
;;; no-op — one special read + a hash-table count — unless the running node
;;; has wallets loaded, and never signals: a wallet failure must not abort
;;; a block connect or a mempool mutation (logged loudly instead; the
;;; wallet re-derives missed state on the next rescan).

(defun %wallet-hook-manager ()
  "The running node's wallet manager when at least one wallet is loaded,
else NIL — the fast-path gate shared by the wallet hooks."
  (let ((manager (and *node* (node-wallet-manager *node*))))
    (and manager
         (bl.rpc:wallet-manager-has-wallets-p manager)
         manager)))

(defun wallet-notify-block-connected (chainstate block block-hash height)
  "Connect-time hook: let loaded wallets scan BLOCK (Core
CWallet::blockConnected). Only the active chainstate's connects are
delivered — an assumeutxo historical (targeted) chainstate's re-derived
old blocks are Core's ChainstateRole::historical, which the wallet ignores
(wallet.cpp:1526-1529)."
  (let ((manager (%wallet-hook-manager)))
    (when (and manager
               (not (bl.store:chain-state-target-blockhash chainstate)))
      (handler-case
          (bl.rpc:wallets-block-connected
           manager (node-mempool *node*) chainstate block block-hash height)
        (error (e)
          (log-error "Wallet processing of connected block at height ~D FAILED: ~A"
                     height e))))))

(defun wallet-notify-block-disconnected (chainstate block height)
  "Reorg hook: let loaded wallets demote BLOCK's transactions (Core
CWallet::blockDisconnected). Called from perform-reorg's commit phase,
tip-first."
  (let ((manager (%wallet-hook-manager)))
    (when (and manager
               (not (bl.store:chain-state-target-blockhash chainstate)))
      (handler-case
          (bl.rpc:wallets-block-disconnected manager block height)
        (error (e)
          (log-error "Wallet processing of disconnected block at height ~D FAILED: ~A"
                     height e))))))

(defun wallet-notify-mempool-tx-added (tx)
  "Mempool hook: Core CWallet::transactionAddedToMempool."
  (let ((manager (%wallet-hook-manager)))
    (when manager
      (handler-case
          (bl.rpc:wallets-mempool-tx-added
           manager (node-mempool *node*) tx)
        (error (e)
          (log-error "Wallet processing of mempool tx add FAILED: ~A" e))))))

(defun wallet-notify-mempool-tx-removed (tx reason)
  "Mempool hook: Core CWallet::transactionRemovedFromMempool. REASON :block
is skipped — the wallet learns about mined txs from the block-connected
hook (Core removeUnchecked, txmempool.cpp:269-275)."
  (unless (eq reason :block)
    (let ((manager (%wallet-hook-manager)))
      (when manager
        (handler-case
            (bl.rpc:wallets-mempool-tx-removed
             manager (node-mempool *node*) tx reason)
          (error (e)
            (log-error "Wallet processing of mempool tx removal FAILED: ~A" e)))))))

(defun %handle-stop-signal ()
  "What SIGTERM/SIGINT does, and ALL it does: set the flag, wake the servicer.
Core HandleSIGTERM (init.cpp:425-431) is one call with the same two effects,
and its comment says the return value is deliberately ignored because a signal
handler has no better way to report a failure.

Nothing here allocates, takes a lock, touches a stream or starts a thread. It
used to do all four — see the commentary on the token pipe above for what that
cost. Whoever services the request does the work: the main-thread watchdog when
one is running (Core's WaitForShutdown), else the servicer thread."
  (unless (sb-ext:cas (symbol-value '*shutdown-request*)
                      nil *signal-shutdown-request*)
    ;; First writer wins; only the winner writes the token, exactly as Core
    ;; guards TokenWrite with m_flag.exchange(true).
    (%write-shutdown-token))
  t)

(defun %run-shutdown-servicer ()
  "Block on the token pipe and service whatever shutdown request wakes us.
Core's WaitForShutdown, moved off the signal path.

When a main-thread watchdog is running it owns the teardown, so this only has
to not interfere: the watchdog's poll sees the same flag. Otherwise — a REPL or
embedded start-node — nobody else would ever run stop-node, so this thread does
it, which is where the old signal handler ran it from."
  (%await-shutdown-token)
  (let ((reason (node-shutdown-requested-p)))
    (when reason
      ;; Logging is safe HERE: an ordinary thread, not a signal context.
      (log-info "Shutdown requested: ~A" reason))
    (unless *shutdown-watchdog-running*
      (ignore-errors (stop-node))
      ;; Per-block script-check worker threads (bt:make-thread :name
      ;; "script-check-N" in validate-block.lisp) are non-daemon and can outlive
      ;; stop-node if validation was in progress when the sync thread was
      ;; destroyed. Without a timeout, sb-ext:exit blocks forever waiting for them
      ;; (incident 2026-05-11: node logged "Node stopped" but SBCL hung 6+
      ;; minutes, eventually needed SIGKILL). Give 5 seconds, then force-exit.
      ;; Core's CCheckQueue (checkqueue.h:206-225) has an explicit stop flag +
      ;; condvar to join workers; ours are ephemeral per-block, not a pool.
      #+sbcl (sb-ext:exit :code (or (cdr *shutdown-request*) +node-exit-clean+)
                          :timeout 5))))

(defun %ensure-shutdown-servicer ()
  "Start the servicer once. Idempotent."
  (%open-shutdown-pipe)
  (unless (and *shutdown-servicer-thread*
               (bt:thread-alive-p *shutdown-servicer-thread*))
    (setf *shutdown-servicer-thread*
          (bt:make-thread #'%run-shutdown-servicer :name "shutdown-servicer")))
  *shutdown-servicer-thread*)

(defun install-shutdown-handler ()
  "Trap SIGTERM and SIGINT so kill <pid> / Ctrl-C calls stop-node and persists
   chain state and UTXO set before exit. Without this, SIGKILL is the only way
   to stop a long-running node and IBD must restart from genesis on next boot.

   Also installs a fail-fast debugger hook: any unhandled error (including
   heap-exhausted) logs a stack and exits non-zero rather than dropping into
   LDB on a tty no one is reading."
  #+sbcl
  (progn
    ;; The servicer (and its pipe) must exist BEFORE the handler can fire:
    ;; a token written to a pipe nobody opened is a lost wake-up.
    (%ensure-shutdown-servicer)
    (let ((handler (lambda (&rest _)
                     (declare (ignore _))
                     ;; No banner line here any more. `format` to a shared
                     ;; stream from a signal handler is exactly the class of
                     ;; call Core's handler exists to avoid, and the servicer
                     ;; logs the same fact one line later from a normal thread.
                     (%handle-stop-signal))))
      (sb-sys:enable-interrupt sb-unix:sigterm handler)
      (sb-sys:enable-interrupt sb-unix:sigint handler)))
  ;; SIGUSR1 toggles sb-sprof profiling. First USR1: start sampling. Second
  ;; USR1: stop, write graph + flat report to /data/bitcoin-lisp/logs/profile.txt.
  ;; Use to identify the hot path during live validation: kill -USR1 <pid> to
  ;; arm, wait through a heavy block, kill -USR1 <pid> again, then read report.
  #+sbcl
  (let ((profiling nil))
    (sb-sys:enable-interrupt
     sb-unix:sigusr1
     (lambda (&rest _)
       (declare (ignore _))
       (cond
         ((not profiling)
          (sb-sprof:reset)
          (sb-sprof:start-profiling :max-samples 200000
                                    :sample-interval 0.001
                                    :mode :cpu
                                    :threads :all)
          (setf profiling t)
          (log-info "[sprof] profiling started"))
         (t
          (sb-sprof:stop-profiling)
          (with-open-file (s "/data/bitcoin-lisp/logs/profile.txt"
                             :direction :output
                             :if-exists :supersede
                             :if-does-not-exist :create)
            (let ((*standard-output* s))
              (format s "=== sb-sprof flat report ===~%")
              (sb-sprof:report :type :flat :max 60)
              (format s "~%~%=== sb-sprof graph report ===~%")
              (sb-sprof:report :type :graph :max 50)))
          (setf profiling nil)
          (log-info "[sprof] profile written to /data/bitcoin-lisp/logs/profile.txt")))))
    (log-info "SIGUSR1 toggles sb-sprof profiling"))
  #+sbcl
  (setf sb-ext:*invoke-debugger-hook*
        (lambda (condition hook)
          (declare (ignore hook))
          (ignore-errors
            (log-error "Fatal: ~A" condition)
            (let ((bt (with-output-to-string (s)
                        (sb-debug:print-backtrace :stream s :count 30))))
              (log-error "Backtrace:~%~A" bt)))
          (sb-ext:exit :code 1))))

(defun %shutdown-flush-chainstates (node)
  "Shutdown flush: every chainstate through the same 3-phase in-transition
commit as the periodic flush, then close its coins DB (Core Shutdown
iterates m_chainstates calling ForceFlushStateToDisk — the marker-protected
FlushStateToDisk/BatchWrite path — then ResetCoinsViews, init.cpp:379-387).
The previous bare save-state + coins-flush pair re-opened the exact crash
window the marker exists to close: killed between the two steps,
chainstate.dat (clean, no marker) was ahead of the coins DB, and startup
loaded the inconsistency silently. Per-chainstate: with an assumeutxo
snapshot active there are two, each owning its own storage-suffix-named
state file and LevelDB. The shared header index is saved inside each flush's
Phase 1."
  (dolist (cs (node-chainstates node))
    (log-info "Flushing chain state~@[ (~A)~]..."
              (let ((suffix (bl.store:chain-state-storage-suffix cs)))
                (and (plusp (length suffix)) suffix)))
    (%flush-chainstate cs :label "Shutdown" :force-full-header-index t)
    (bl.store:close-chainstate-coins-view cs)))

(defun stop-node ()
  "Stop the running Bitcoin node: the full teardown, ending with the
*shutdown-complete* latch. Returns T when this call performed the teardown.

Concurrency: the FIRST caller owns the shutdown. A second, overlapping call
does not run the teardown again — two runs would drive %flush-chainstate
through the same fixed chainstate.dat.tmp path (storage/utxo.lisp) and
double-close the same LevelDB handles — it waits for the owner to finish and
returns NIL. Prefer request-node-shutdown from anything that is not the main
thread; see the shutdown-coordination section above."
  (unless *node*
    (return-from stop-node nil))
  ;; CAS rather than a lock: reachable from the SIGTERM handler, which runs in
  ;; whichever thread the signal interrupted.
  (unless (null (sb-ext:cas (symbol-value '*stop-node-in-progress*) nil t))
    (log-info "Shutdown already in progress on another thread; waiting for it")
    (wait-for-shutdown-complete)
    (return-from stop-node nil))
  (unwind-protect
       (%stop-node)
    ;; The latch is stop-node's FINAL act: the watchdog (and any concurrent
    ;; caller) waits on it, so it must be set strictly after the flush,
    ;; mempool.dat, peers.dat, banlist and wallet writes below — never before.
    (setf *stop-node-in-progress* nil
          *shutdown-complete* t)))

(defun %stop-node ()
  "stop-node's teardown proper; run by exactly one thread (see stop-node)."
  (log-info "Stopping node...")
  ;; Whatever start-node got to, it is not building any more. Clearing here (not
  ;; only on start-node's success path) keeps a failed start from leaving the
  ;; latch set, which would make a later REPL Ctrl-C register a request nobody
  ;; services.
  (setf *node-starting* nil)

  ;; Persist reconnection anchors while peers are still connected (before the
  ;; teardown below disconnects them).
  (save-anchors *node*)

  ;; -shutdownnotify runs FIRST and is WAITED for (Core ShutdownNotify,
  ;; init.cpp:255-266): a hook that fires after the process is gone, or races
  ;; it, is a hook that may not run at all.
  (run-shutdown-notify)

  ;; Stop RPC server first. Warmup is the SERVER's state, cleared by
  ;; stop-rpc-server — re-arming it here left it armed for anything else in the
  ;; image, which in the test suite meant every later request answered -28.
  (bl.rpc:stop-rpc-server)

  ;; Signal the node to stop. request-ibd-stop reaches the IBD inner
  ;; loops, which can otherwise run for hours after node-running flips
  ;; (the outer sync loop only checks between run-ibd passes).
  (setf (node-running *node*) nil)
  (bl.net:request-ibd-stop)

  ;; Stop the torcontrol client: closing the control connection is what tears
  ;; the ephemeral onion service down inside Tor (no DEL_ONION, like Core).
  (when (node-tor-controller *node*)
    (bl.net:stop-tor-control (node-tor-controller *node*))
    (setf (node-tor-controller *node*) nil))

  ;; Stop the inbound listeners: close the sockets (unblocks accept) and let
  ;; the accept threads observe node-running=nil and exit (accept timeout 1s).
  (when (node-listener-socket *node*)
    (bl.net:close-listener (node-listener-socket *node*))
    (setf (node-listener-socket *node*) nil))
  (when (node-onion-listener-socket *node*)
    (bl.net:close-listener (node-onion-listener-socket *node*))
    (setf (node-onion-listener-socket *node*) nil))
  ;; One shared deadline bounds the TOTAL wait for both accept threads.
  (let ((deadline (+ (get-internal-real-time) (* 5 internal-time-units-per-second))))
    (bl.net:join-thread-or-destroy
     (node-listener-thread *node*) :deadline deadline)
    (bl.net:join-thread-or-destroy
     (node-onion-listener-thread *node*) :deadline deadline))
  (setf (node-listener-thread *node*) nil
        (node-onion-listener-thread *node*) nil)
  ;; Disconnect any inbound peers not yet merged into the peer list. The listener
  ;; thread is already joined above, but take the lock for consistency.
  (let ((pending (bt:with-recursive-lock-held ((node-lock *node*))
                   (prog1 (node-pending-inbound-peers *node*)
                     (setf (node-pending-inbound-peers *node*) nil)))))
    (dolist (peer pending)
      (handler-case (bl.net:disconnect-peer peer) (error () nil))))

  ;; Wait for sync thread to finish (with timeout)
  (when (and (node-sync-thread *node*)
             (bt:thread-alive-p (node-sync-thread *node*)))
    (log-info "Waiting for sync thread to stop...")
    (let ((deadline (+ (get-internal-real-time)
                       ;; 10 minutes — long enough that a single heavy block's
                       ;; validation finishes and connect-block updates UTXO set
                       ;; + chain tip atomically, so destroy-thread fallback
                       ;; (which can corrupt mid-update state) is virtually
                       ;; never needed. A reorg no longer holds the thread to its
                       ;; end either — perform-reorg truncates on a block boundary
                       ;; (plan phase 3b). Deliberately NOT shortened: a tighter
                       ;; deadline would only make the destroy path more likely.
                       (* 600 internal-time-units-per-second))))
      (loop while (and (bt:thread-alive-p (node-sync-thread *node*))
                       (< (get-internal-real-time) deadline))
            do (sleep 0.1))
      (when (bt:thread-alive-p (node-sync-thread *node*))
        (log-warn "Sync thread did not stop gracefully, destroying...")
        (bt:destroy-thread (node-sync-thread *node*)))))
  (setf (node-sync-thread *node*) nil)

  ;; Disconnect all peers
  (log-info "Disconnecting peers...")
  (dolist (peer (node-peers *node*))
    (handler-case
        (bl.net:disconnect-peer peer)
      (error (c)
        (log-warn "Error disconnecting peer: ~A" c))))
  (bt:with-recursive-lock-held ((node-lock *node*))
    (setf (node-peers *node*) nil))

  ;; Flush every chainstate through the crash-safe 3-phase commit and close
  ;; its coins view (see %shutdown-flush-chainstates).
  (%shutdown-flush-chainstates *node*)

  ;; Save fee statistics
  (when (node-fee-estimator *node*)
    (log-info "Saving fee statistics...")
    (bl.mp:save-fee-stats (node-fee-estimator *node*)))

  ;; Save mempool (Core DumpMempool)
  (let ((path (bl.mp:mempool-dat-path (node-data-directory *node*))))
    (when (and path (node-mempool *node*))
      (log-info "Saving mempool (~D entries)..."
                (bl.mp:save-mempool-file (node-mempool *node*) path))))

  ;; Save peer address book
  (when (node-address-book *node*)
    (log-info "Saving peer address book...")
    (bl.net:save-address-book
     (node-address-book *node*)
     (bl.net:peers-dat-path (node-data-directory *node*))))

  ;; Final banlist dump (Core ~BanMan calls DumpBanlist, banman.cpp:26),
  ;; then detach the path so post-shutdown mutations stop writing.
  (bl.net:save-banlist)
  (setf bl.net:*banlist-path* nil)

  ;; Unload wallets (writes each wallet's best-block marker, closes its DB)
  (when (node-wallet-manager *node*)
    (log-info "Unloading wallets...")
    (bl.rpc:close-wallet-manager (node-wallet-manager *node*))
    (setf (node-wallet-manager *node*) nil))

  ;; Close transaction index
  (when (node-tx-index *node*)
    (log-info "Closing transaction index...")
    (bl.store:close-tx-index (node-tx-index *node*)))

  ;; Drop the prune locks before the DBs they read close. Each lock is a thunk
  ;; holding the index object, so leaving them registered keeps a stopped
  ;; node's indexes reachable AND leaves the thunks callable against closed
  ;; LevelDB handles — a live hazard in a test image that starts several nodes,
  ;; since the next PRUNE-LOCK-CEILING would consult the previous node's index.
  (bl.store:clear-prune-locks)

  ;; Close block filter index
  (when (node-blockfilterindex *node*)
    (log-info "Closing block filter index...")
    (bl.store:close-blockfilterindex (node-blockfilterindex *node*)))

  ;; Close coinstats index
  (when (node-coinstatsindex *node*)
    (log-info "Closing coinstats index...")
    (bl.store:close-coinstatsindex (node-coinstatsindex *node*)))

  ;; Close the spender index. Its LevelDB handle is no different from the
  ;; others' — leaving it open on shutdown leaks the handle and leaves the
  ;; database without a clean close.
  (when (node-txospenderindex *node*)
    (log-info "Closing spender index...")
    (bl.store:close-txospender-index (node-txospenderindex *node*)))

  ;; Cleanup secp256k1
  (bl.crypto:cleanup-secp256k1)

  ;; Stop the script-check workers (Core's CCheckQueue is stopped with the
  ;; validation interface). They hold no resources but would keep the process
  ;; alive, and a pool left running across a restart-in-one-image would be
  ;; sized for the previous -par.
  (ignore-errors (bl.val:stop-script-check-pool))

  ;; Close the ZMQ publishers before the directory lock: a subscriber should
  ;; see the node go away, not hold a socket to a process that has released
  ;; everything else.
  (zmq-stop-publishers)

  ;; Release the data-directory lock last: everything above may still touch
  ;; the directory, and a successor node must not open it until they are done.
  (unlock-data-directory)
  (remove-pid-file)

  (log-info "Node stopped")

  (setf *node* nil)
  t)

;;;; Peer Management

;;;; Anchor connections (Bitcoin Core anchors.dat)
;;;;
;;;; On shutdown we persist a couple of currently-connected outbound peers and
;;;; reconnect to them first on the next start, BEFORE consulting DNS seeds.
;;;; This closes the across-restart eclipse window: a freshly-started node that
;;;; relied only on DNS seeds (or a poisoned addrman) could be fed an attacker's
;;;; peer set, but a known-good anchor it was just connected to cannot be
;;;; substituted by the attacker. (Core anchors are block-relay-only peers;
;;;; dedicated block-relay-only outbound slots are a separate follow-up — these
;;;; anchors are drawn from the regular outbound pool.)

(defparameter +max-anchors+ 2
  "How many outbound peers to persist as reconnection anchors (Core saves 2).")

(defconstant +anchors-magic-v1+ #x414e4331)  ; "ANC1" — bare IP strings, no port
(defconstant +anchors-magic-v2+ #x414e4332)  ; "ANC2" — network-typed + port

(defvar *pending-anchor-addresses* nil
  "Anchor dial candidates — (host-string . port) conses, port NIL meaning the
network default — loaded at startup and consumed (and cleared) by the first
connect-to-peers so they are attempted before DNS-seed candidates.")

(defun anchors-dat-path (data-directory)
  "Path to anchors.dat in DATA-DIRECTORY."
  (merge-pathnames "anchors.dat" data-directory))

(defun save-anchor-entries (path entries)
  "Write anchor ENTRIES — a list of (network bytes port) — to PATH in the v2
format: magic \"ANC2\", count byte, then per entry a BIP155-style net id,
length-prefixed address bytes and a big-endian port (crash-safe: temp +
fsync + atomic rename, CRC32-protected)."
  (bl.store:save-file-with-crc32
   path
   (lambda (stream)
     (loop for shift in '(24 16 8 0)
           do (write-byte (ldb (byte 8 shift) +anchors-magic-v2+) stream))
     (write-byte (length entries) stream)
     (dolist (e entries)
       (destructuring-bind (net bytes port) e
         (write-byte (bl.net:network-key-id net) stream)
         (write-byte (length bytes) stream)
         (write-sequence bytes stream)
         (write-byte (ldb (byte 8 8) port) stream)
         (write-byte (ldb (byte 8 0) port) stream))))))

(defun parse-anchor-entries (bytes)
  "Parse anchors.dat payload BYTES (CRC already verified) into a list of
(network bytes port). Reads the v2 network-typed format; a v1 file (bare IP
strings without port) is MIGRATED: each string is parsed to a typed address,
with the port NIL (caller substitutes the network default — all v1-era
anchors were dialed at the default port anyway). Unparseable v1 entries
(e.g. a hostname from addnode) are dropped. Returns NIL for unknown magic."
  (let ((end (- (length bytes) 4))              ; stay inside payload (before CRC)
        (magic (logior (ash (aref bytes 0) 24) (ash (aref bytes 1) 16)
                       (ash (aref bytes 2) 8) (aref bytes 3)))
        (entries '()))
    (cond
      ((= magic +anchors-magic-v2+)
       (let ((count (aref bytes 4)) (pos 5))
         (dotimes (i count)
           (when (< (+ pos 2) end)
             (let ((net (bl.net:key-id-network (aref bytes pos)))
                   (len (aref bytes (1+ pos))))
               (incf pos 2)
               (when (and net (<= (+ pos len 2) end))
                 (push (list net
                             (coerce (subseq bytes pos (+ pos len))
                                     '(simple-array (unsigned-byte 8) (*)))
                             (logior (ash (aref bytes (+ pos len)) 8)
                                     (aref bytes (+ pos len 1))))
                       entries))
               (incf pos (+ len 2)))))))
      ((= magic +anchors-magic-v1+)
       (let ((count (aref bytes 4)) (pos 5))
         (dotimes (i count)
           (when (< pos end)
             (let ((len (aref bytes pos)))
               (incf pos)
               (when (<= (+ pos len) end)
                 (multiple-value-bind (net addr-bytes)
                     (bl.net:parse-network-address
                      (map 'string #'code-char (subseq bytes pos (+ pos len))))
                   (when net
                     (push (list net addr-bytes nil) entries)))
                 (incf pos len)))))))
      (t (return-from parse-anchor-entries nil)))
    (nreverse entries)))

(defun save-anchors (node)
  "Persist up to +max-anchors+ currently-connected outbound peers to
anchors.dat in the network-typed v2 format (net + address + port)."
  (let* ((ready-outbound
           (remove-if-not
            (lambda (p) (and (not (bl.net:peer-inbound p))
                             (eq (bl.net:peer-state p) :ready)))
            (node-peers node)))
         ;; Prefer block-relay-only peers as anchors (Core anchors are
         ;; block-relay: an attacker who fed us a poisoned addrman can't
         ;; substitute a peer we were just block-relay-connected to). Fall back
         ;; to full-relay outbound if we have no block-relay peers.
         (block-relay (remove-if-not
                       (lambda (p) (eq (bl.net:peer-conn-type p)
                                       :block-relay))
                       ready-outbound))
         (ready (or block-relay ready-outbound))
         (default-port (network-port (node-network node)))
         (entries
           (loop for p in (subseq ready 0 (min +max-anchors+ (length ready)))
                 for (net bytes) = (multiple-value-list
                                    (bl.net:parse-network-address
                                     (bl.net:peer-address p)))
                 when net                        ; hostname peers (addnode) skipped
                   collect (list net bytes
                                 (let ((conn (bl.net::peer-connection p)))
                                   (if conn
                                       (bl.net::connection-port conn)
                                       default-port))))))
    (when entries
      (handler-case
          (save-anchor-entries (anchors-dat-path (node-data-directory node)) entries)
        (error (e) (log-warn "Failed to save anchors: ~A" e)))
      (log-info "Saved ~D anchor peer~:P" (length entries)))))

(defun load-anchors (node)
  "Read anchors.dat into *pending-anchor-addresses* — (host . port) dial
candidates, dialed at the STORED port (migrated v1 entries carry port NIL and
fall back to the network default) — so the next connect attempts them first.
Reading CONSUMES the file, as Core's ReadAnchors does (addrdb.cpp:234-246):
anchors are one-shot, so a crash loop cannot re-dial the same two block-relay
peers on every start and pin an already-eclipsed node to them. The next clean
shutdown rewrites it. Missing/corrupt file is ignored; a v1-era file migrates
(see parse-anchor-entries) and the next save rewrites it as v2. Only networks that
are dialable under the current config (dialable-network-p: onion needs a Tor
proxy, cjdns needs -cjdnsreachable) and reachable (-onlynet) become dial
candidates."
  (let* ((path (anchors-dat-path (node-data-directory node)))
         (bytes (bl.store:load-file-with-crc32 path 6)))
    ;; Unconditionally, parse failure included (Core ReadAnchors). A failure
    ;; here leaves the anchors in place, which silently restores the pinning
    ;; this prevents — so say so rather than swallowing it.
    (handler-case (delete-file path)
      (file-error () )
      (error (c) (log-debug "Could not consume ~A: ~A" path c)))
    (when bytes
      (setf *pending-anchor-addresses*
            (loop for (net addr-bytes port) in (parse-anchor-entries bytes)
                  when (and (bl.net:dialable-network-p net)
                            (bl.net:reachable-network-p net))
                    collect (cons (bl.net:network-address-to-string
                                   net addr-bytes)
                                  port)))
      (when *pending-anchor-addresses*
        (log-info "Loaded ~D anchor peer~:P for priority reconnection"
                  (length *pending-anchor-addresses*))))))

(defun %reachable-seed-addresses (addresses)
  "Keep only the seed-derived ADDRESSES (strings) we may actually dial.

An address LITERAL survives when -onlynet still permits its network. Seed
lists — DNS-seed results and the hardcoded fixed seeds — are clearnet by
construction, so under -onlynet=onion (or cjdns-only) dialing them is a direct
deanonymizing clearnet TCP connection. Core never hits this because seeds go
into addrman and every dial candidate is filtered by g_reachable_nets at
selection time (ThreadOpenConnections); we build the dial list directly, so the
filter has to happen here. The addrman branch above is already filtered by
select-dialable-address, and anchors by load-anchors.

A candidate parse-network-address cannot classify is a HOSTNAME, and survives
only when a SOCKS5 proxy is configured AND clearnet is reachable. Under -proxy
discover-peers deliberately returns the seed hostnames UNRESOLVED (protocol.lisp)
— resolving them locally would leak a plaintext DNS query outside the tunnel —
and make-tcp-connection hands each one to the proxy inside the SOCKS5 CONNECT
(ATYP DOMAINNAME, socks5.lisp) for the proxy to resolve. That mirrors Core's
'if (HaveNameProxy()) AddAddrFetch(seed)' (net.cpp:2356-2357): a proxied seed
stays dialable BY NAME. Dropping those unconditionally (this filter's behaviour
as first written, PR #306) left a proxied node with a fresh datadir zero dial
candidates on mainnet/signet/testnet3 — they have hostname DNS seeds and no
fixed-seed list, so it could not bootstrap at all.

The clearnet conjunct keeps the -onlynet privacy guarantee closed HERE, not
merely upstream: a DNS seed answers with A/AAAA records, so a hostname
candidate is a clearnet candidate however it gets resolved. It cannot cost a
dial in any configuration apply-config-globals can produce, since an -onlynet
excluding IPv4 and IPv6 already soft-sets -dnsseed=0 (config.lisp, Core
init.cpp:835-844) so no hostname ever reaches this function, and with no proxy
discover-peers emits IP literals only.

Applies to SEED candidates only: manual -addnode/-connect targets are
deliberately exempt from -onlynet, matching Core."
  (let ((name-proxy-p
          (and bl.net:*proxy*
               (or (bl.net:reachable-network-p :ipv4)
                   (bl.net:reachable-network-p :ipv6))
               t)))
    (remove-if-not (lambda (addr)
                     (let ((net (bl.net:parse-network-address addr)))
                       (if net
                           (bl.net:reachable-network-p net)
                           name-proxy-p)))
                   addresses)))

(defun %record-dial-attempt (node host port)
  "Stamp an addrman dial attempt for HOST:PORT — Core CConnman::ConnectNode
calls addrman.Attempt() on EVERY dial, immediately after the attempt and before
the socket is examined (net.cpp:492-497).

We recorded attempts from exactly one place, the failure branch of
connect-to-peers, and that function runs only at startup and when the peer
count hits zero. Every steady-state dial — replace-disconnected-peers,
establish-outbound-peer (and so maintain-block-relay-peers), and the feeler —
recorded nothing, so nAttempts stayed 0 for addresses we had tried and failed
repeatedly. addrman's whole quality signal is that counter: without it the
selection cannot age out dead addresses, the feeler that exists to prove the
tried table cannot mark anything bad, and we keep re-dialing and re-gossiping
the same corpses. That is an eclipse-resistance and getaddr-hygiene loss, not a
crash.

Good() resets the counter on a successful VERSION, so stamping every dial does
not penalise addresses that work."
  (let ((address-book (node-address-book node)))
    (when address-book
      (multiple-value-bind (net ip-bytes)
          (bl.net:parse-network-address host)
        (when net
          (ignore-errors
           (bl.net:address-book-attempt
            address-book ip-bytes port :count-failure t :net net)))))))

(defun %seed-address-book-from-dns (node)
  "Query the DNS seeds and put what they return into the address book, the way
Core's ThreadDNSAddressSeed does (net.cpp:2340-2360).

Runs in its own thread so start-up is not blocked on DNS, which is also why
Core makes it a thread. Failures are logged and dropped: a node that cannot
reach a seed still has its address book, its -connect peers and its fixed
seeds."
  (let ((book (node-address-book node))
        ;; PEER-ADDRESS's PORT slot is an (unsigned-byte 16); a DNS seed
        ;; answers with bare addresses, so they take the network's default
        ;; port, exactly as Core's ThreadDNSAddressSeed does.
        (port (network-port (node-network node))))
    (when book
      (bt:make-thread
       (lambda ()
         (handler-case
             (let ((added 0))
               (dolist (addr (bl.net:discover-peers))
                 (multiple-value-bind (net ip-bytes)
                     (bl.net:parse-network-address addr)
                   (when (and net
                              (not (bl.net:address-book-lookup
                                    book ip-bytes port net)))
                     (when (bl.net:address-book-add
                            book
                            (bl.net:make-peer-address
                             :net net :ip ip-bytes :port port :services 0
                             :last-seen (bl.ser:get-unix-time)))
                       (incf added)))))
               (log-info "DNS seeds contributed ~D new address~:P" added))
           (error (e)
             (log-warn "DNS seeding failed: ~A" e))))
       :name "bitcoin-dnsseed-thread"))))

(defun %record-outbound-result (address-book addr port peer success)
  "Record an outbound dial outcome for ADDR:PORT in ADDRESS-BOOK, adding the
entry if new (network-typed, so IPv6/onion/cjdns peers get addrman credit
too): SUCCESS => Good + Connected, failure => Attempt with count-failure
(Core CConnman's addrman feedback in ConnectNode/OpenNetworkConnection).
Hostname dial targets (unparseable as addresses) are skipped."
  (when address-book
    (multiple-value-bind (net ip-bytes)
        (bl.net:parse-network-address addr)
      (when net
        (unless (bl.net:address-book-lookup
                 address-book ip-bytes port net)
          (bl.net:address-book-add
           address-book
           (bl.net:make-peer-address
            :net net :ip ip-bytes :port port
            :services (if (and success peer)
                          (bl.net:peer-services peer)
                          0)
            :last-seen (bl.ser:get-unix-time))))
        (if success
            (progn
              (bl.net:address-book-good
               address-book ip-bytes port
               (bl.ser:get-unix-time) net)
              (bl.net:address-book-connected
               address-book ip-bytes port
               (bl.ser:get-unix-time) net))
            (bl.net:address-book-attempt
             address-book ip-bytes port :count-failure t :net net))))))

(defun connect-to-peers (node max-peers &key (timeout 60) (min-peers 1))
  "Connect to Bitcoin network peers.
Uses address book for warm starts, falls back to DNS seeds. Dial candidates
are (host . port) conses (port NIL = network default): addrman picks and
anchors carry their STORED ports, DNS/fixed seeds the default. Onion default
port = chain default port (Core net.cpp:3395-3404 GetDefaultPort), so the
same fallback covers .onion candidates.
MAX-PEERS: Target number of peers to connect
TIMEOUT: Maximum seconds to spend connecting (default 60)
MIN-PEERS: Return early once we have at least this many peers (default 1)
Returns the number of peers connected."
  ;; setnetworkactive off: make no outbound connections.
  (unless (node-network-active node)
    (return-from connect-to-peers 0))
  ;; -connect: the only outbound peers are the specified ones, dialed by
  ;; connect-specified-nodes. Returning 0 here rather than dialing them makes
  ;; the two paths one path — the startup dial and the maintenance dial cannot
  ;; disagree about which targets are current.
  (unless (addrman-outgoing-enabled-p)
    (connect-specified-nodes node)
    (return-from connect-to-peers (length (node-peers node))))
  (let ((address-book (node-address-book node))
        (addresses '()))
    ;; Warm start: select peers from the addrman (new/tried buckets,
    ;; eclipse-resistant) rather than a single global score ranking.
    (when (and address-book
               (>= (bl.net:address-book-count address-book) 8))
      (bl.net:resolve-tried-collisions address-book)
      (log-info "Using peer address book (~D entries)..."
                (bl.net:address-book-count address-book))
      (let ((seen (make-hash-table :test 'equal))
            (picks '()))
        (dotimes (i (* max-peers 8))
          ;; select-dialable-address, never raw select: post-BIP155 the book
          ;; can hold records not dialable under the current config (torv3
          ;; without a Tor proxy, i2p always, cjdns without -cjdnsreachable).
          (let ((pa (bl.net:select-dialable-address address-book)))
            (when pa
              (let ((str (bl.net:peer-address-string pa))
                    (port (bl.net:peer-address-port pa)))
                (unless (gethash str seen)
                  (setf (gethash str seen) t)
                  (push (cons str (and (plusp port) port)) picks))))))
        (setf addresses (nreverse picks))))
    ;; ⚠️ The DNS query used to live HERE, gated on "not enough candidates". It
    ;; is now a start-up step that feeds the ADDRESS BOOK
    ;; (%SEED-ADDRESS-BOOK-FROM-DNS), which is Core's shape: ThreadDNSAddressSeed
    ;; runs with connman and is independent of how any one dial is going.
    ;;
    ;; -forcednsseed still belongs here, because it means "query even though the
    ;; address book looks full" — a statement about this decision, not about
    ;; start-up (Core DEFAULT_FORCEDNSSEED, net.h:97). It does NOT override
    ;; -dnsseed=0, the same precedence Core's thread has.
    (when (and *force-dns-seed* *dns-seed-enabled*)
      (log-info "Discovering peers from DNS seeds...")
      (let* ((dns-addrs (bl.net:discover-peers))
             (usable (%reachable-seed-addresses dns-addrs)))
        (log-info "Found ~D potential peers from DNS~:[~; (~:*~D dialable under -onlynet)~]"
                  (length dns-addrs)
                  (and (/= (length usable) (length dns-addrs)) (length usable)))
        (setf addresses (append addresses
                                (mapcar (lambda (a) (cons a nil)) usable)))
        (setf addresses (remove-duplicates addresses :key #'car :test #'string=))))

    ;; Fixed-seed fallback for testnet4: even after DNS, the candidate pool
    ;; may have only one /16 group (sprovoost.nl seed has been dark since
    ;; ~2026-05; wiz.biz returns its own /24 cluster only). Mirrors Bitcoin
    ;; Core's vFixedSeeds population in chainparams.cpp — used as a
    ;; last-resort source so we always have netgroup diversity available.
    (let ((fixed (bl.chain:chain-params-fixed-seeds
                  (bl.chain:find-chain-params (node-network node)))))
      (when (and fixed
                 ;; -fixedseeds=0 forbids the hardcoded fallback (Core
                 ;; net.cpp:2571-2572 "Fixed seeds are disabled").
                 *fixed-seeds-enabled*
                 (let ((groups (remove-duplicates
                                (remove nil (mapcar (lambda (c)
                                                      (bl.net:ip-netgroup
                                                       (car c)))
                                                    addresses))
                                :test #'string=)))
                   (< (length groups) 8)))
        (log-info "Merging ~A fixed-seed list (~D peers, ~D /16 groups)"
                  (node-network node) (length fixed)
                  (length (remove-duplicates (mapcar #'bl.net:ip-netgroup fixed)
                                             :test #'string=)))
        (setf addresses
              (remove-duplicates
               (append addresses
                       (mapcar (lambda (a) (cons a nil))
                               (%reachable-seed-addresses fixed)))
               :key #'car :test #'string=))))

    ;; Diversify by /16 netgroup so the first 8 connection attempts spread
    ;; across distinct operators (incident 2026-05-11: 8-of-8 peers were
    ;; from 103.165.192.x wiz.biz nodes — one stall stalled the whole
    ;; sync). Mirrors Bitcoin Core's addrman netgroup bucket selection
    ;; (netaddress.cpp CNetAddr::GetGroup).
    (setf addresses (bl.net:diversify-by-netgroup addresses
                                                                   :key #'car))

    ;; Anchors first (Core anchors.dat): reconnect to the peers we persisted at
    ;; last shutdown before any DNS/addrman candidate, then consume them so
    ;; later reconnect cycles use the normal pool.
    (when *pending-anchor-addresses*
      (setf addresses (remove-duplicates (append *pending-anchor-addresses* addresses)
                                         :key #'car :test #'string= :from-end t))
      (setf *pending-anchor-addresses* nil))

    (log-info "~D candidate peers available" (length addresses))

    ;; Store discovered addresses for reconnection
    (setf (node-known-addresses node) addresses)

    (let ((connected 0)
          (start-time (get-internal-real-time))
          (timeout-ticks (* timeout internal-time-units-per-second)))
      (dolist (candidate (node-known-addresses node))
        ;; Stop if we have enough peers
        (when (>= connected max-peers)
          (return))

        ;; Check timeout - but only exit early if we have minimum peers
        (when (and (>= connected min-peers)
                   (> (- (get-internal-real-time) start-time) timeout-ticks))
          (log-info "Connection timeout reached with ~D peers" connected)
          (return))

        (let* ((addr (car candidate))
               (dial-port (or (cdr candidate) (network-port (node-network node)))))
          (log-debug "Trying to connect to ~A..." addr)
          (handler-case
              (let ((peer (bl.net:connect-peer addr dial-port)))
                (when peer
                  (setf (bl.net:peer-address peer) addr)
                  (log-info "Connected to ~A" addr)
                  ;; Perform handshake
                  (when (bl.net:perform-handshake peer :near-tip (bl.net:near-tip-p (node-chain-state node)))
                    (log-info "Handshake complete with ~A (~A, height ~D)"
                              addr
                              (bl.net:peer-user-agent peer)
                              (bl.net:peer-start-height peer))
                    ;; Send feature negotiation messages
                    (bl.net:send-post-handshake-messages peer)
                    ;; Record success in address book (add if not present)
                    (%record-outbound-result address-book addr dial-port peer t)
                    ;; Send compact block negotiation (BIP 152)
                    (bl.net:send-compact-block-negotiation peer)
                    (bt:with-recursive-lock-held ((node-lock node))
                      (push peer (node-peers node)))
                    (incf connected))
                  (unless (eq (bl.net:peer-state peer) :ready)
                    (bl.net:disconnect-peer peer))))
            (error (c)
              (log-debug "Failed to connect to ~A: ~A" addr c)
              ;; Record failure in address book (add if not present)
              (%record-outbound-result address-book addr dial-port nil nil)))))

      (log-info "Connected to ~D peer~:P" connected)
      connected)))

;;;; Peer Health and Reconnection

(defun check-peers-health (node)
  "Check health of all peers. Disconnect unresponsive ones.
Also checks compact block reconstruction timeouts (BIP 152)."
  (let ((to-disconnect '()))
    (dolist (peer (node-peers node))
      ;; Both checks below can WRITE (ping, compact-block getdata); a peer
      ;; that FIN'd since the last drain raises stream-error from that
      ;; write. Fold any error into :disconnect instead of letting it
      ;; escape — this runs on the sync thread, whose outer handler-case
      ;; would otherwise end the thread (2026-05-09 incident pattern).
      (handler-case
          (progn
            ;; Check compact block timeout
            (bl.net:check-compact-block-timeout peer)
            ;; Check ping/pong health
            (let ((status (bl.net:check-peer-health peer)))
              (when (eq status :disconnect)
                (push peer to-disconnect))))
        (error () (push peer to-disconnect))))
    (dolist (peer to-disconnect)
      (log-warn "Disconnecting unresponsive peer ~A"
                (bl.net:peer-address peer))
      (handler-case
          (bl.net:disconnect-peer peer)
        (error (c) (declare (ignore c))))
      (bt:with-recursive-lock-held ((node-lock node))
        (setf (node-peers node) (remove peer (node-peers node)))))
    (length to-disconnect)))

(defun outbound-full-relay-peer-p (peer)
  "T iff PEER is a ready outbound full-relay connection — the only kind that
counts toward the outbound full-relay target (Core CNode::IsFullOutboundConn:
m_conn_type == OUTBOUND_FULL_RELAY, which is never inbound). Inbound peers
and block-relay/feeler outbound peers are deliberately excluded."
  (and (eq (bl.net:peer-state peer) :ready)
       (not (bl.net:peer-inbound peer))
       (eq (bl.net:peer-conn-type peer) :outbound-full-relay)))

(defun count-outbound-full-relay-peers (peers)
  "Count ready outbound full-relay peers among PEERS (Core nOutboundFullRelay).
Inbound connections are excluded so an attacker filling our inbound slots
cannot suppress replacement outbound dials (eclipse-attack prevention)."
  (count-if #'outbound-full-relay-peer-p peers))

(defconstant +pow-target-spacing-seconds+ 600
  "Core consensus.nPowTargetSpacing. It is 10*60 on EVERY network Core ships —
mainnet, testnet3, testnet4, signet and regtest (kernel/chainparams.cpp:98,
229, 336, 486, 577) — so the stale-tip threshold below needs no per-network
case, and regtest is testable against it without a special fixture.")

(defconstant +stale-tip-age-seconds+ (* 3 +pow-target-spacing-seconds+)
  "Core TipMayBeStale's threshold: nPowTargetSpacing * 3 = 1800s
(net_processing.cpp:1339). The factor is THREE. Earlier revisions of
docs/eclipse-resistance-plan.md wrote it as `30 * 600 = 1800s' — right product,
wrong factor — which lands on 18000s, five hours, if copied literally. Written
as the multiplication rather than the number so the two can never drift apart.")

(defconstant +stale-tip-check-interval-seconds+ 600
  "Core STALE_CHECK_INTERVAL (net_processing.cpp:108). This gates the stale-tip
half ALONE and is nested inside the 45s sweep — the two cadences are different
and both real. Checking staleness every 45s instead would re-evaluate a
1800s-old condition forty times before it could change.")

(defvar *last-stale-tip-check* 0
  "Unix time of the last stale-tip evaluation (Core m_stale_tip_check_time).")

(defvar *try-new-outbound-peer* nil
  "Core CConnman::m_try_another_outbound_peer. While true the dialer may open
ONE full-relay connection beyond node-max-peers.

Note what this does NOT do: it does not raise the eviction target. Core's
GetExtraFullOutboundCount still measures against the unraised
m_max_outbound_full_relay (net.cpp:2473), so the moment the extra peer connects
the rotation sees one peer too many and drops the stalest. That is the whole
mechanism — the extra slot buys a REPLACEMENT, not a bigger peer set. Raising
both targets together, the intuitive reading, would make the extra peer
permanent and the rotation would never fire at all.")

(defun outbound-dial-budget (node)
  "How many outbound full-relay connections the DIALER may hold: node-max-peers,
plus one while the stale-tip extra slot is granted.

Core opens that extra peer from a SEPARATE branch of ThreadOpenConnections
(net.cpp:2722), reached only after the normal full-relay and block-relay
targets are already satisfied — so it is exactly one connection more than we
would otherwise dial, and only while the tip looks stuck.

The eviction target is deliberately NOT this number (see
consider-outbound-evictions): Core's GetExtraFullOutboundCount measures against
the unraised maximum, so the extra peer is immediately one too many and the
rotation drops the stalest. Dialing budget and eviction budget differing by one
IS the mechanism; making them agree would turn a replacement into permanent
growth and silence the rotation."
  (+ (node-max-peers node) (if *try-new-outbound-peer* 1 0)))

(defun tip-may-be-stale-p (node)
  "Core PeerManagerImpl::TipMayBeStale (net_processing.cpp:1332): our tip has
not advanced in +STALE-TIP-AGE-SECONDS+ and no block is in flight from anyone.

The elapsed time is computed as a DIFFERENCE within get-node-time, never
by converting an epoch. node-last-tip-advance-time is universal time while
every other timer in this subsystem is unix seconds, and the plan records a
~2.2e9-second error from feeding one clock's value to the other. A difference
is epoch-independent, so there is nothing here to get wrong.

A node whose tip has never advanced stamps the clock and reports fresh, as
Core does for m_last_tip_update == 0 — otherwise every node would declare
itself eclipsed the moment it started."
  (let ((last (node-last-tip-advance-time node)))
    (cond ((not (plusp last))
           (setf (node-last-tip-advance-time node) (bl.ser:get-node-time))
           nil)
          (t (and (> (- (bl.ser:get-node-time) last) +stale-tip-age-seconds+)
                  (not (bl.net:any-blocks-in-flight-p)))))))

(defun check-for-stale-tip (node now)
  "Core's stale-tip half of CheckForStaleTipAndEvictPeers (:5468-5479), on its
own 10-minute timer. Sets or clears the extra-outbound permission.

The CLEAR is not optional and is the half that is easy to omit: without it the
first stale episode raises the dialing budget permanently, and the rotation —
which measures against the unraised target — then spends every 45s sweep
evicting a peer we just dialled. The feature would present as steady outbound
churn with no stale tip in sight.

Core guards this with three conditions; we carry one. GetNetworkActive is
node-network-active below. GetUseAddrmanOutgoing has no counterpart because we
have no -connect option — if one is ever added, it must gate this, or a node
pinned to a fixed peer list would start dialling addrman peers behind the
operator's back. LoadingBlocks likewise has no counterpart; in its place the
in-flight condition inside tip-may-be-stale-p keeps a node that is actively
fetching from calling its own tip stale."
  (when (> now *last-stale-tip-check*)
    (setf *last-stale-tip-check* (+ now +stale-tip-check-interval-seconds+))
    (cond ((and (node-network-active node)
                (tip-may-be-stale-p node))
           (unless *try-new-outbound-peer*
             (log-info "Potential stale tip detected (no advance in ~Ds); \
allowing one extra outbound peer"
                       (- (bl.ser:get-node-time) (node-last-tip-advance-time node))))
           (setf *try-new-outbound-peer* t))
          (*try-new-outbound-peer*
           (log-info "Tip is advancing again; releasing the extra outbound slot")
           (setf *try-new-outbound-peer* nil)))))

(defun replace-disconnected-peers (node)
  "Replace disconnected peers to maintain target peer count.
Returns the number of new peers connected."
  ;; Reap disconnected peers first — this also cleans up peers that
  ;; setnetworkactive dropped, even while networking stays disabled.
  (bt:with-recursive-lock-held ((node-lock node))
    (setf (node-peers node)
          (remove-if (lambda (p)
                       (eq (bl.net:peer-state p) :disconnected))
                     (node-peers node))))
  ;; setnetworkactive off: don't dial replacements.
  (unless (node-network-active node)
    (return-from replace-disconnected-peers 0))
  ;; -connect: this node picks no peers of its own. The reap above still runs —
  ;; a dead -connect peer must leave the list so connect-specified-nodes redials
  ;; it — but nothing here chooses a replacement from the address book.
  (unless (addrman-outgoing-enabled-p)
    (return-from replace-disconnected-peers 0))
  ;; Count ONLY outbound full-relay peers toward the outbound target — never
  ;; inbound, never block-relay/feeler. Core's ThreadOpenConnections counts
  ;; nOutboundFullRelay via IsFullOutboundConn() (net.cpp:2648-2657,2718) and
  ;; explicitly keeps inbound out of the arithmetic: inbound connections are
  ;; free for an attacker to make, so letting them satisfy the outbound
  ;; target is an eclipse primitive — 8 attacker inbounds previously
  ;; suppressed dialing any honest outbound replacement here. The inbound
  ;; population has its own separate cap (*max-inbound-connections*, enforced at
  ;; merge time in merge-inbound-peers). Block-relay-only peers are a
  ;; separate additive pool maintained by maintain-block-relay-peers (Core
  ;; keeps m_max_outbound_block_relay distinct from
  ;; m_max_outbound_full_relay); folding them in here would let 2 idle
  ;; block-relay slots starve replacement of a dropped full-relay peer.
  ;; (Known simplification vs Core: addnode peers are typed
  ;; :outbound-full-relay in our code, so they do count here, whereas Core's
  ;; MANUAL connections are additive.)
  (let* ((active-count (count-outbound-full-relay-peers (node-peers node)))
         (needed (- (outbound-dial-budget node) active-count)))
    (when (<= needed 0)
      (return-from replace-disconnected-peers 0))

    ;; Get addresses already in use
    (let* ((used-addrs (mapcar #'bl.net:peer-address
                               (node-peers node)))
           (used-groups (remove nil (mapcar #'bl.net:ip-netgroup
                                            used-addrs)))
           (connected 0))
      ;; Core ThreadOpenConnections skips a candidate whose /16 netgroup
      ;; already holds an outbound peer (setConnected, net.cpp:2651, 2685,
      ;; 2826). connect-to-peers spreads the INITIAL set, but replacements
      ;; had no netgroup test at all, so hours of churn could concentrate the
      ;; outbound set in one group — half of an eclipse's preconditions.
      (dolist (candidate (node-known-addresses node))
        ;; Stop attempting new connect+handshake cycles the moment shutdown is
        ;; requested — each one can otherwise block (connect timeout + handshake
        ;; read) and delay the sync thread reaching its node-running checkpoint.
        (when (or (>= connected needed)
                  (bl.net:ibd-stop-requested-p))
          (return))
        (let ((addr (car candidate)))
          (unless (or (member addr used-addrs :test #'string=)
                      (let ((g (bl.net:ip-netgroup addr)))
                        (and g (member g used-groups :test #'equal))))
            (handler-case
                (let* ((dial-port (or (cdr candidate)
                                      (network-port (node-network node))))
                       (peer (progn
                               (%record-dial-attempt node addr dial-port)
                               (bl.net:connect-peer addr dial-port))))
                  (when peer
                    (setf (bl.net:peer-address peer) addr)
                    (when (bl.net:perform-handshake peer :near-tip (bl.net:near-tip-p (node-chain-state node)))
                      (log-info "Replacement peer connected: ~A" addr)
                      ;; Send feature negotiation messages
                      (bl.net:send-post-handshake-messages peer)
                      ;; Send compact block negotiation (BIP 152)
                      (bl.net:send-compact-block-negotiation peer)
                      (bt:with-recursive-lock-held ((node-lock node))
                        (push peer (node-peers node)))
                      (incf connected))
                    (unless (eq (bl.net:peer-state peer) :ready)
                      (bl.net:disconnect-peer peer))))
              (error (c)
                (declare (ignore c)))))))
      connected)))

;;;; Manually-added peers (addnode)

(defun parse-node-endpoint (node spec)
  "Split an addnode SPEC into (values host port). Accepts \"host\",
\"host:port\", and \"[ipv6]:port\"; bare or bracketless addresses default to the
network's P2P port. A trailing :port is only honored when it is all digits, so a
bare IPv6 address (which contains colons) is treated as host-only."
  (let ((default-port (network-port (node-network node))))
    (cond
      ;; [ipv6]:port  or  [ipv6]
      ((and (plusp (length spec)) (char= (char spec 0) #\[))
       (let ((close (position #\] spec)))
         (if (null close)
             (values spec default-port)
             (let ((host (subseq spec 1 close))
                   (rest (subseq spec (1+ close))))
               (if (and (plusp (length rest)) (char= (char rest 0) #\:)
                        (plusp (length (subseq rest 1)))
                        (every #'digit-char-p (subseq rest 1)))
                   (values host (parse-integer rest :start 1))
                   (values host default-port))))))
      (t
       (let ((colon (position #\: spec :from-end t)))
         (if (and colon
                  (< (1+ colon) (length spec))
                  (every #'digit-char-p (subseq spec (1+ colon)))
                  ;; A single colon => host:port; multiple => bare IPv6.
                  (= colon (position #\: spec)))
             (values (subseq spec 0 colon) (parse-integer spec :start (1+ colon)))
             (values spec default-port)))))))

(defconstant +behind-retry-seconds+ 5
  "Seconds the sync loop's between-pass wait runs before giving up on the rest
of its 30-second cycle WHEN we hold headers above our own tip.

Not a poll interval — the wait already ends immediately on a new header
announcement. This covers the other order: headers that arrived during the sync
pass itself, where there is known work and nobody left to announce it. Bounded
rather than immediate so a chain no peer will serve retries on a timer instead
of spinning, which is the same reason the download loop has a no-progress
yield.")

(defun peer-connected-to-host-p (node host)
  "T if a peer at address HOST is currently in the node's peer list, ignoring
ports (Core AlreadyConnectedToAddress, net.cpp:347-351).

This is the guard for dials with NO destination string — the ones sourced from
addrman — which is the only place Core applies it. A dial that names a
destination uses PEER-CONNECTED-TO-ENDPOINT-P instead; see there for why the
difference is not cosmetic."
  (bt:with-recursive-lock-held ((node-lock node))
    (and (find host (node-peers node)
               :key #'bl.net:peer-address :test #'string=)
         t)))

(defun peer-connected-to-endpoint-p (node host port)
  "T if a peer at HOST:PORT is currently in the node's peer list (Core
AlreadyConnectedToHost, net.cpp:335-339).

The guard for every dial that names a destination: -addnode, `addnode onetry`,
-connect, -seednode. Core compares the full destination against each peer's
m_addr_name, and an INBOUND peer's name carries the ephemeral source port, so
an inbound connection from a host never blocks an outbound dial to it. Ours has
the same property for the same reason: an accepted connection records port 0
while a dialed one records the port it dialed.

Matching on HOST ALONE — which this used to do — is wrong wherever two peers
can share an address, and on regtest EVERY node is 127.0.0.1. One connection to
loopback then blocked every other, so a node could never hold more than one
connection to the local machine: the second `connect_nodes` in any Core
functional test found no new peer and timed out. Nothing looked wrong from
inside the node, which had simply been asked to dial a host it was already
talking to."
  (bt:with-recursive-lock-held ((node-lock node))
    (and (find-if (lambda (p)
                    (let ((conn (bl.net::peer-connection p)))
                      (and conn
                           (string= host (bl.net::connection-host conn))
                           (eql port (bl.net::connection-port conn)))))
                  (node-peers node))
         t)))

(defun establish-outbound-peer (node host port &key (conn-type :outbound-full-relay) manual)
  "Full outbound connect + handshake to HOST:PORT, pushing the ready peer onto
node-peers. CONN-TYPE (:outbound-full-relay or :block-relay) sets the peer's
connection type; MANUAL tags an operator-pinned (-addnode / addnode onetry)
peer, Core's ConnectionType::MANUAL — set BEFORE the handshake, because the
VERSION-time services gate exempts manual peers (Core ExpectServicesFromConn)
and connect-added-nodes redials a missing added node every ~30 s, so gating one
would loop forever. Returns the peer or NIL. MUST run on the sync thread so
node-peers stays single-writer. No-op when networking is disabled."
  (when (node-network-active node)
    (handler-case
        (let ((peer (progn (%record-dial-attempt node host port)
                           (bl.net:connect-peer host port))))
          (when peer
            (setf (bl.net:peer-address peer) host)
            (when manual (setf (bl.net:peer-manual peer) t))
            (if (bl.net:perform-handshake peer :conn-type conn-type
                                                        :near-tip (bl.net:near-tip-p (node-chain-state node)))
                (progn
                  (bl.net:send-post-handshake-messages peer)
                  (bl.net:send-compact-block-negotiation peer)
                  (bt:with-recursive-lock-held ((node-lock node))
                    (push peer (node-peers node)))
                  (log-info "Added-node peer connected: ~A" host)
                  peer)
                (progn (bl.net:disconnect-peer peer) nil))))
      (error (c)
        (log-debug "Added-node connect to ~A:~D failed: ~A" host port c)
        nil))))

(defun connect-seed-nodes (node)
  "Dial each -seednode once as an addr-fetch peer (Core ProcessAddrFetch,
net.cpp). The handshake already sends GETADDR for any non-block-relay outbound
peer, so the fetch needs no extra message; the peer disconnects itself from the
addr handler once it answers.

Skipped entirely when -connect is in force, which is Core's behaviour by
construction: ThreadOpenConnections takes the specified-addresses branch (or is
never started) and never reaches the seed queue."
  (when (and (node-network-active node) (addrman-outgoing-enabled-p) *seed-nodes*)
    (dolist (spec *seed-nodes*)
      (multiple-value-bind (host port) (parse-node-endpoint node spec)
        (unless (peer-connected-to-endpoint-p node host port)
          (log-info "Fetching addresses from -seednode ~A" spec)
          (establish-outbound-peer node host port :conn-type :addr-fetch))))))

(defun connect-specified-nodes (node)
  "Keep every -connect target connected (Core ThreadOpenConnections' first
branch, net.cpp: MANUAL connections dialed in a loop for as long as the node
runs). Distinct from connect-added-nodes only in which list it walks."
  (when (node-network-active node)
    (dolist (spec *connect-nodes*)
      (multiple-value-bind (host port) (parse-node-endpoint node spec)
        (unless (peer-connected-to-endpoint-p node host port)
          (establish-outbound-peer node host port :manual t))))))

(defun connect-added-nodes (node)
  "Service addnode requests on the sync thread: drain one-shot \"onetry\" dials,
then keep every \"add\" peer connected. Honors network-active."
  (when (node-network-active node)
    ;; One-shot onetry dials (Core addnode onetry).
    (let ((onetry (bt:with-recursive-lock-held ((node-lock node))
                    (prog1 (node-pending-onetry node)
                      (setf (node-pending-onetry node) nil)))))
      (dolist (spec onetry)
        (multiple-value-bind (host port) (parse-node-endpoint node spec)
          (unless (peer-connected-to-endpoint-p node host port)
            (establish-outbound-peer node host port :manual t)))))
    ;; addconnection (regtest testing RPC): one dial per request, of the
    ;; connection TYPE the caller named — which is the whole point of the RPC,
    ;; since a test cannot otherwise ask for a block-relay or feeler slot.
    (let ((queued (bt:with-recursive-lock-held ((node-lock node))
                    (prog1 (nreverse *pending-test-connections*)
                      (setf *pending-test-connections* nil)))))
      (dolist (request queued)
        (multiple-value-bind (host port) (parse-node-endpoint node (car request))
          (establish-outbound-peer node host port :conn-type (cdr request)))))
    ;; Maintain persistent added-node connections.
    (dolist (spec (node-added-nodes node))
      (multiple-value-bind (host port) (parse-node-endpoint node spec)
        (unless (peer-connected-to-endpoint-p node host port)
          (establish-outbound-peer node host port :manual t))))))

(defconstant +target-block-relay-peers+ 2
  "Dedicated block-relay-only outbound slots (Bitcoin Core opens 2). They carry
blocks/headers but no tx relay -- anti-partition insurance and the source of
reconnection anchors.")

(defun automatic-inbound-capacity (max-connections max-outbound-full-relay)
  "Core CConnman::Init (net.h:1110-1113): inbound capacity is the automatic
connection total less the automatic outbound slots — MAX-OUTBOUND-FULL-RELAY,
the block-relay-only slots (clamped to what remains, as Core clamps them) and
one feeler — never negative. MAX-OUTBOUND-FULL-RELAY is our :max-peers, which
is this node's m_max_outbound_full_relay and is deliberately NOT clamped to
Core's min(8, total): it is an operator knob here (run-node.sh sets 16)."
  (let* ((block-relay (max 0 (min +target-block-relay-peers+
                                  (- max-connections max-outbound-full-relay))))
         (feeler 1))
    (max 0 (- max-connections max-outbound-full-relay block-relay feeler))))

(defconstant +feeler-interval-seconds+ 120
  "Minimum spacing between feeler probes (Core FEELER_INTERVAL averages ~2 min).")

(defvar *last-feeler-time* 0
  "GET-NODE-TIME of the last feeler attempt, for rate-limiting.")

(defun peers-of-conn-type (node type)
  "Count current peers whose connection type is TYPE."
  (bt:with-recursive-lock-held ((node-lock node))
    (count type (node-peers node)
           :key #'bl.net:peer-conn-type)))

(defun %addrman-pick-unconnected (node &key new-only)
  "Pick an addrman address (as (values host port)) we're not already connected
to, or NIL; PORT is NIL when the record has none stored (caller substitutes
the network default). NEW-ONLY restricts to the 'new' table (for feelers).
Goes through select-dialable-address so automatic slots (block-relay,
feelers) only ever draw records dialable under the current config (torv3
needs a Tor proxy, cjdns needs -cjdnsreachable, i2p never)."
  (let ((ab (node-address-book node)))
    (when ab
      (dotimes (_ 20)
        (let ((pa (bl.net:select-dialable-address ab :new-only new-only)))
          (when pa
            (let ((host (bl.net:peer-address-string pa))
                  (port (bl.net:peer-address-port pa)))
              (unless (peer-connected-to-host-p node host)
                (return-from %addrman-pick-unconnected
                  (values host (and (plusp port) port)))))))))))

(defun maintain-block-relay-peers (node)
  "Ensure up to +target-block-relay-peers+ block-relay-only outbound peers.
Each carries blocks/headers only (relay=0), never tx relay."
  (when (and (node-network-active node) (node-address-book node)
             (addrman-outgoing-enabled-p))
    (loop while (< (peers-of-conn-type node :block-relay) +target-block-relay-peers+)
          do (multiple-value-bind (ip port) (%addrman-pick-unconnected node)
               (unless (and ip (establish-outbound-peer
                                node ip (or port (network-port (node-network node)))
                                :conn-type :block-relay))
                 ;; No candidate, or the connect failed: stop trying this cycle.
                 (return))
               (log-info "Opened block-relay-only peer ~A" ip)))))

(defun do-feeler-connection (node host port)
  "Open a short-lived feeler connection: connect, handshake, and on success mark
the address good (promoting it new -> tried). Always disconnects afterward --
feelers exist only to validate addrman's tried table (Core anti-eclipse), never
to join the peer set."
  (handler-case
      (let ((peer (progn (%record-dial-attempt node host port)
                         (bl.net:connect-peer host port))))
        (when peer
          (setf (bl.net:peer-address peer) host)
          (when (bl.net:perform-handshake peer :conn-type :feeler)
            (multiple-value-bind (net ip-bytes)
                (bl.net:parse-network-address host)
              (when net
                (bl.net:address-book-good
                 (node-address-book node) ip-bytes port
                 (bl.ser:get-unix-time) net)))
            (log-debug "Feeler validated ~A (new -> tried)" host))
          (bl.net:disconnect-peer peer)))
    (error (c)
      (log-debug "Feeler to ~A:~D failed: ~A" host port c))))

(defun maybe-do-feeler (node)
  "Rate-limited feeler probe. Core ThreadOpenConnections (net.cpp:2796-2812)
spends the feeler on a tried-table COLLISION first — testing the incumbent
before resolve-tried-collisions may evict it — and only otherwise validates a
'new' address into 'tried'. An incumbent we are already connected to needs no
probe: mark it good, which resolves the collision in its favour, and spend the
feeler on the new table instead."
  (let ((now (bl.ser:get-node-time)))
    (when (and (node-network-active node) (node-address-book node)
               (addrman-outgoing-enabled-p)
               (>= (- now *last-feeler-time*) +feeler-interval-seconds+))
      (setf *last-feeler-time* now)
      (let* ((book (node-address-book node))
             (incumbent (bl.net:select-tried-collision book))
             (host (and incumbent
                        (bl.net:peer-address-string incumbent))))
        (when (and host (peer-connected-to-host-p node host))
          (bl.net:address-book-good
           book (bl.net:peer-address-ip incumbent)
           (bl.net:peer-address-port incumbent)
           (bl.ser:get-unix-time)
           (bl.net:peer-address-network incumbent))
          (setf host nil))
        (multiple-value-bind (ip port)
            (if host
                (values host (let ((p (bl.net:peer-address-port incumbent)))
                               (and (plusp p) p)))
                (%addrman-pick-unconnected node :new-only t))
          (when ip
            (do-feeler-connection node ip (or port (network-port (node-network node))))))))))

(defvar *last-chain-sync-check* 0
  "Unix time of the last chain-sync eviction sweep. Node-scoped, NOT local to
run-ibd: run-ibd is re-entered on every outer sync cycle, so a loop-local
timestamp would reset each pass and the cadence would be meaningless.")

(defconstant +extra-peer-check-interval-seconds+ 45
  "Core EXTRA_PEER_CHECK_INTERVAL — cadence of the chain-sync sweep.")

(defun consider-outbound-evictions (node)
  "Core's CheckForStaleTipAndEvictPeers tick (net_processing.cpp:5460), on the
45s EXTRA_PEER_CHECK_INTERVAL cadence. Driven from here rather than from
run-ibd's block-download loop, which does not run at tip — exactly where
eclipse resistance matters.

Two sweeps, in Core's order: the per-peer chain-sync eviction, then the
whole-set extra-outbound eviction."
  (let ((now (bl.ser:get-unix-time)))
    (when (>= (- now *last-chain-sync-check*) +extra-peer-check-interval-seconds+)
      (setf *last-chain-sync-check* now)
      (let ((chain-state (node-current-chainstate node)))
        (when chain-state
          (dolist (peer (node-peers node))
            (handler-case
                (bl.net:consider-chain-sync-eviction
                 peer chain-state now)
              (error (e)
                ;; Per-peer, so one unhappy peer cannot stop the sweep — but
                ;; LOGGED, not swallowed. A silent error here exempts that peer
                ;; from eviction forever, which is indistinguishable from the
                ;; eclipse this code exists to prevent.
                (log-warn "Chain-sync eviction failed for peer ~A: ~A"
                          (bl.net:peer-address peer) e))))))
      ;; Core runs EvictExtraOutboundPeers from this same tick (:5466), and
      ;; BEFORE the stale-tip check rather than after: the peer we are about to
      ;; decide we need is not one we should have dropped on the way in.
      ;;
      ;; Unlike the chain-sync sweep this one is not per-peer — both halves
      ;; rank the set against itself — so it takes the list once, snapshotted
      ;; under the node lock: disconnect-peer runs inside it and mutates state
      ;; the listener thread touches too.
      (handler-case
          (bl.net:evict-extra-outbound-peers
        (bt:with-recursive-lock-held ((node-lock node)) (copy-list (node-peers node)))
        now
        ;; Deliberately the UNRAISED target, even while the extra-outbound slot
        ;; is granted. Core's GetExtraFullOutboundCount does the same
        ;; (net.cpp:2473): the extra peer is supposed to put us one over so the
        ;; rotation drops the stalest one. Passing the raised budget here would
        ;; make the extra connection permanent and silently disable the whole
        ;; rotation.
        (node-max-peers node)
        +target-block-relay-peers+)
        ;; Whole-set, so an error takes the sweep with it — which is exactly
        ;; why it must be visible. This feature's own history is a sweep placed
        ;; where it never ran (see the docstring above); a bare ignore-errors
        ;; would recreate that silently.
        (error (e) (log-warn "Extra-outbound eviction sweep failed: ~A" e)))
      ;; Then the stale-tip half, on its own 10-minute timer. Core's order
      ;; (:5466 then :5468): evict first, so a peer we are about to decide we
      ;; need is not one we just dropped on the way in.
      (handler-case (check-for-stale-tip node now)
        (error (e) (log-warn "Stale-tip check failed: ~A" e))))))

(defun maintain-peers (node)
  "Run periodic peer maintenance: health checks, reconnection, dedicated
block-relay-only slots, an occasional feeler probe, and the chain-sync
eviction sweep."
  (check-peers-health node)
  (connect-added-nodes node)
  (connect-specified-nodes node)
  ;; Core resolves tried-table collisions once per ThreadOpenConnections
  ;; iteration (net.cpp:2768), not only at startup — otherwise, once the
  ;; collision set is full, address-book-good stops recording successes.
  (let ((book (node-address-book node)))
    (when book (bl.net:resolve-tried-collisions book)))
  (consider-outbound-evictions node)
  (replace-disconnected-peers node)
  (maintain-block-relay-peers node)
  (maybe-do-feeler node))

;;;; Blockchain Synchronization

(defun node->context (node chainstate)
  "The node-context (bl.ctx) a sync pass or receive pump acts on: CHAINSTATE
(the current one) with its coins view, and the node's shared pieces. One
builder for the sync pass and the between-cycles tick, so the two cannot
drift -- the first review of the node-context change found the tick still
calling the old signature and no production path filling PEERS."
  (bl.ctx:make-node-context
   :chain-state chainstate
   :utxo-set (bl.store:chain-state-coins-view chainstate)
   :block-store (node-block-store node)
   :mempool (node-mempool node)
   :peers (node-peers node)
   :fee-estimator (node-fee-estimator node)
   :address-book (node-address-book node)
   :recent-rejects (node-recent-rejects node)
   :historical-chainstate (node-historical-chainstate node)))

(defun sync-blockchain (node)
  "Run one IBD/follow-tip cycle against connected peers.

Doesn't short-circuit on `peer-start-height` since that value is frozen
at handshake and goes stale once the chain advances — start-ibd's
header-sync phase is what discovers new tips, and its block-download
phase exits quickly when there's nothing new to fetch."
  (unless (node-peers node)
    (log-warn "No peers connected, cannot sync")
    (return-from sync-blockchain 0))

  ;; A non-empty peer list is NOT enough. Peers enter NODE-PEERS only after a
  ;; successful handshake, but they stay in the list once they go
  ;; :DISCONNECTED — reaping is REPLACE-DISCONNECTED-PEERS' job, reached via
  ;; MAINTAIN-PEERS, which the sync loop runs AFTER this function. So a list of
  ;; nothing but dead peers is reachable, and FIND-BEST-PEER (which only counts
  ;; :READY) returns NIL for it. Handing that NIL to the PEER-START-HEIGHT
  ;; accessor is a type error that unwinds the whole sync iteration, so
  ;; maintain-peers never runs, so the dead peers are never reaped or redialed,
  ;; so the next iteration fails identically: the failure feeds itself. Proven
  ;; live — a node logged this type error every 5 seconds for 19 days, 333k
  ;; times, holding 8 peers it would never replace.
  (let ((best-peer (find-best-peer node)))
    (unless best-peer
      (log-warn "No peer has completed its handshake yet; skipping this sync cycle")
      (return-from sync-blockchain 0))

    ;; IBD drives the current chainstate (its tip and coins view). When an
    ;; assumeutxo background sync is active, the historical chainstate rides
    ;; along as a second download cursor inside the same IBD pass: run-ibd
    ;; queues its [historical-tip .. snapshot-base] range and routes received
    ;; blocks to whichever chainstate owns their height.
    (let ((chainstate (node-current-chainstate node))
          (peer-height (bl.net:peer-start-height best-peer)))
      (log-debug "Sync cycle: local height ~D, peer-start height ~D"
                 (bl.store:current-height chainstate)
                 peer-height)
      (bl.net::start-ibd
       (node-peers node)
       (node->context node chainstate)
       peer-height))))


(defun find-best-peer (node)
  "Find the best peer for syncing (highest block height)."
  (let ((ready-peers (remove-if-not
                      (lambda (p)
                        (eq (bl.net:peer-state p) :ready))
                      (node-peers node))))
    (when ready-peers
      (first (sort (copy-list ready-peers) #'>
                   :key #'bl.net:peer-start-height)))))

;;;; Status and Info

(defun node-status ()
  "Print the current node status."
  (unless *node*
    (format t "Node is not running.~%")
    (return-from node-status nil))

  (format t "~%=== Bitcoin-Lisp Node Status ===~%")
  (format t "Network: ~A~%" (node-network *node*))
  (format t "Running: ~A~%" (if (node-running *node*) "Yes" "No"))
  (format t "Syncing: ~A~%" (if (node-syncing *node*) "Yes" "No"))
  (when (node-sync-thread *node*)
    (format t "Sync thread: ~A~%"
            (if (bt:thread-alive-p (node-sync-thread *node*)) "Active" "Stopped")))
  (format t "Data directory: ~A~%" (node-data-directory *node*))
  (format t "~%Chain State:~%")
  (when (node-chain-state *node*)
    (format t "  Height: ~D~%"
            (bl.store:current-height (node-chain-state *node*)))
    (format t "  Best block: ~A~%"
            (bl.crypto:bytes-to-hex
             (bl.store:best-block-hash (node-chain-state *node*)))))
  (format t "~%UTXO Set:~%")
  (when (node-utxo-set *node*)
    (format t "  UTXOs: ~D~%"
            (bl.store:utxo-count (node-utxo-set *node*))))
  (format t "~%Mempool:~%")
  (when (node-mempool *node*)
    (format t "  Transactions: ~D~%"
            (bl.mp:mempool-count (node-mempool *node*)))
    (format t "  Size: ~:D vbytes (~:D bytes memory)~%"
            (bl.mp:mempool-total-size (node-mempool *node*))
            (bl.mp:mempool-dynamic-usage (node-mempool *node*))))
  (format t "~%Peers:~%")
  (if (node-peers *node*)
      (dolist (peer (node-peers *node*))
        (format t "  - ~A (height ~D, latency ~Dms)~%"
                (bl.net:peer-user-agent peer)
                (bl.net:peer-start-height peer)
                (bl.net:peer-ping-latency peer)))
      (format t "  (no peers connected)~%"))
  (format t "~%")
  t)


