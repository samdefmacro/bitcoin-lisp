(in-package #:bitcoin-lisp)

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

(defun %init-logging (data-directory network log-level log-file console-log pid-file block-notify shutdown-notify debug-categories debug-exclude log-time-micros log-thread-names log-level-specs)
  "Core AppInitMain Step 4a, application initialization: the log file and level,
per-category thresholds, the deferred config lines, the operator hooks, the pid
file and -debug / -debugexclude -- everything that must exist before the first
log line of the node itself."
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
      (log-info "Debug logging categories: ~{~A~^ ~}" enabled))))


(defun %init-parameters (network txindex blockfilterindex prune dbcache-mib mocktime test-activation-heights coinstatsindex txospenderindex reindex-chainstate peer-block-filters port)
  "The startup parameters applied before any database opens: test activation
heights, -mocktime, -prune validation and -port (Core init.cpp Steps 3-4),
the -dbcache split (Core's Step 7 CalculateCacheSizes) and the -externalip
resolvability check (its Step 6)."
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
  ;; happens after the tor block in %START-NETWORK-SERVICES, whose clear-local-addresses would
  ;; otherwise wipe it.
  (dolist (spec bl.net:*external-ips*)
    (unless (bl.net:parse-network-address spec)
      (error "Cannot resolve -externalip address: '~A'" spec))))


(defun %init-datadir-layout (data-directory network migrate-datadir)
  "Datadir layout (Core doc/files.md): -migratedatadir and the legacy-layout
report, both BEFORE init-node opens the databases."
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
                  (first entry) (third entry) (second entry)))))))


(defun %init-connection-options (data-directory network max-peers max-connections accept-stale-fee-estimates connect-nodes connect-nodes-supplied-p seednode asmap whitelist whitebind network-active addnode blocksonly)
  "Connection options applied before any peer can connect: -blocksonly,
-networkactive, -asmap, -whitelist / -whitebind, -acceptstalefeeestimates
(Core Step 6) and -addnode / -connect / -seednode (Step 12's connection setup)."
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
        (log-info "-addnode peers are dialed alongside -connect")))))


(defun %init-shutdown-latches (log-rate-limit flat-block-files)
  "Re-arm every once-per-run latch for this run -- -stopatheight, the shutdown
coordination, the signal handler, the peers.dat dump clock, the log rate
limiter, the block-file format -- so an in-image restart never inherits a
previous node's state."
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
  ;; end of START-NODE. Core does the same: registerSignalHandler runs in
  ;; AppInitBasicSetup (init.cpp:902), a thousand lines before LoadMempool
  ;; (init.cpp:2047). Installed last, every slow startup step ran with SIGTERM
  ;; at its DEFAULT disposition, so a stop during the mempool import, an index
  ;; backfill (hours) or a wallet rescan killed the process outright instead of
  ;; being recorded. Now it registers the request, the loops that poll
  ;; interrupt-requested-p give up at their next boundary, and the watchdog
  ;; services it once START-NODE returns.
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
  (setf bl.store:*flat-block-files* (and flat-block-files t)))


(defun %init-lock-and-banner (network)
  "The startup banner (Core InitLogging), the datadir lock
(AppInitLockDirectories), SIGHUP log reopening, ZMQ publishers and the
pruning mode announcement (Step 3)."
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
        (log-info "Transaction relay: DISABLED (safety default)"))))


(defun %init-load-chain (network reindex)
  "Core Step 7, LoadChainstate: chain state, block store, coins view, header
index, -reindex, and the block-store <-> header-index position map."
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
  ;; %IMPORT-EXTERNAL-BLOCK-FILES (called from START-NODE), which runs after validation is ready.

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
        (log-info "Block file accounting: ~D flat block file~:P" files)))))

(defun %init-recover-chain (reindex-chainstate)
  "Core Step 7 after LoadChainstate: the assumeutxo snapshot chainstate, crash
recovery of an interrupted flush, snapshot validation at startup, undo storage
and its pruned-horizon sweep, and -reindex-chainstate -- everything that needs
the chain, store and coins view open and settles the tip before any block can
connect."
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
  ;; index init (%START-INDEXES, from %INIT-SERVICES), which then bind the single
  ;; promoted chainstate.
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
    (do-reindex-chainstate)))


(defun %init-services (network txindex blockfilterindex rpc-port rpc-bind rpc-bind-supplied-p rpc-user rpc-password rpc-auth rpc-allow-ip coinstatsindex txospenderindex reindex-chainstate force-compact-db webui webui-supplied-p webui-path webui-open rest-enabled)
  "The RPC server, up early (Core Step 4a AppInitServers, answering
RPC_IN_WARMUP while the rest loads); the recent-rejects filter, the fee
estimator, the address book and banlist (Step 6); mempool.dat (Step 11); the
anchors (Step 12); the coins-DB tip reconciliation; the indexes (Step 8) and
-forcecompactdb."
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
    (force-compact-databases)))


(defun %init-peer-features-and-wallet (network v2transport peer-block-filters tx-reconciliation wallet wallet-supplied-p wallet-names)
  "The service flags advertised to peers (BIP157 serving, BIP330
reconciliation, BIP324 v2 transport; Core Steps 3 and 6), the secp256k1
context (Step 4) and, Core Step 9, the wallet manager with the wallets
recorded for startup."
  ;; BIP157 filter serving (-peerblockfilters): gated in %INIT-PARAMETERS on the block filter
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
            (bl.wallet:init-wallet-manager (node-data-directory *node*)
                                                  network))
      (log-info "Wallet support enabled (descriptor wallets under ~A)"
                (merge-pathnames "wallets/" (node-data-directory *node*)))
      ;; Core LoadWallets (load.cpp:118): load every wallet recorded for
      ;; startup in settings.json. Runs here because the chainstate (%INIT-LOAD-CHAIN)
      ;; and the mempool (load-mempool-from-disk) are both up, so each wallet
      ;; can catch up from its locator and fold in the mempool; networking has
      ;; not started, so no block can connect underneath the catch-up.
      (bl.wallet:load-wallets-on-startup *node* wallet-names))))


(defun %sync-thread-loop (max-peers)
  "Core Step 12's sync thread: reset the per-process sync state, then run the
IBD / follow-tip cycle with peer maintenance until the node stops. Runs on
its own thread; the body catches and retries transient iteration errors."
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
                               (bl.wallet:wallets-maybe-resend *node*)
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


(defun %start-network-services (network sync listen listen-bind listen-onion tor-control tor-password)
  "Core Step 12, start node: DNS seeding into the address book, the inbound
listener, the onion listener with its Tor control connection, and
-externalip's AddLocal entries."
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
  ;; Validated resolvable in %INIT-PARAMETERS; runs after the tor block so its
  ;; clear-local-addresses cannot wipe these entries.
  (dolist (spec bl.net:*external-ips*)
    (multiple-value-bind (net bytes)
        (bl.net:parse-network-address spec)
      (when net
        (bl.net:add-local
         net bytes (listen-port network)
         bl.net:+local-manual+)))))

(defun %finish-init-and-start-sync (rpc-port startup-notify sync max-peers)
  "Core Step 13 (finished): mark the node running, end RPC warmup and fire
-startupnotify; then Core Step 12's sync thread (%SYNC-THREAD-LOOP), with the
per-process sync state and the at-tip liveness signal reset for this run."
  (setf (node-running *node*) t)

  ;; The RPC server is UP by now (%start-rpc-early, from %INIT-SERVICES); the node is
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
           (lambda () (%sync-thread-loop max-peers))
           :name "bitcoin-sync-thread"))))

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

  (%init-logging data-directory network log-level log-file console-log pid-file block-notify shutdown-notify debug-categories debug-exclude log-time-micros log-thread-names log-level-specs)
  (%init-parameters network txindex blockfilterindex prune dbcache-mib mocktime test-activation-heights coinstatsindex txospenderindex reindex-chainstate peer-block-filters port)
  (%init-datadir-layout data-directory network migrate-datadir)
  ;; Initialize node: the node struct and its databases; the chain itself is
  ;; loaded by %init-load-chain below.
  (setf *node* (init-node data-directory :network network :log-level log-level))
  (setf (node-max-peers *node*) max-peers)
  (%init-connection-options data-directory network max-peers max-connections accept-stale-fee-estimates connect-nodes connect-nodes-supplied-p seednode asmap whitelist whitebind network-active addnode blocksonly)
  (%init-shutdown-latches log-rate-limit flat-block-files)
  (%init-lock-and-banner network)
  (%init-load-chain network reindex)
  (%init-recover-chain reindex-chainstate)
  (%init-services network txindex blockfilterindex rpc-port rpc-bind rpc-bind-supplied-p rpc-user rpc-password rpc-auth rpc-allow-ip coinstatsindex txospenderindex reindex-chainstate force-compact-db webui webui-supplied-p webui-path webui-open rest-enabled)
  (%init-peer-features-and-wallet network v2transport peer-block-filters tx-reconciliation wallet wallet-supplied-p wallet-names)
  (%finish-init-and-start-sync rpc-port startup-notify sync max-peers)

  (%start-network-services network sync listen listen-bind listen-onion tor-control tor-password)
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
      ;; keyword) from the same merged config, before launching. *NETWORK* is
      ;; set first: -acceptnonstdtxn's refusal on mainnet reads it, and until
      ;; this line it still held the default while init-node set it later --
      ;; so the "not currently supported for main chain" error Core's
      ;; feature_config_args.py expects could never fire.
      (setf *network* settings-network)
      (apply-config-globals merged)
      ;; The RPC half, which config.lisp cannot express (see
      ;; APPLY-RPC-CONFIG-GLOBALS).
      (apply-rpc-config-globals merged)
      ;; datadir only comes from the CLI/default (locating the conf needs it), so
      ;; make sure it reaches start-node even if it wasn't in the scalar scan.
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
