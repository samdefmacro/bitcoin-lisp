(in-package #:bitcoin-lisp)

#+sbcl
(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :sb-sprof))

;;; Bitcoin Node
;;;
;;; Main entry point for the Bitcoin full node.
;;; Coordinates all subsystems: networking, storage, validation.

;;;; Network Configuration

(defconstant +testnet3+ :testnet3)
(defconstant +testnet4+ :testnet4)
(defconstant +signet+ :signet)
(defconstant +mainnet+ :mainnet)

(defconstant +regtest+ :regtest)

(defvar *network* +testnet4+
  "Current network mode (:testnet3, :testnet4, :signet, :regtest, or :mainnet).")

(defun network-magic (network)
  "Return the network magic bytes for NETWORK."
  (ecase network
    (:testnet3 bitcoin-lisp.serialization:+testnet3-magic+)
    (:testnet4 bitcoin-lisp.serialization:+testnet4-magic+)
    (:signet bitcoin-lisp.serialization:+signet-magic+)
    (:regtest bitcoin-lisp.serialization:+regtest-magic+)
    (:mainnet bitcoin-lisp.serialization:+mainnet-magic+)))

(defun network-port (network)
  "Return the default port for NETWORK."
  (ecase network
    (:testnet3 18333)
    (:testnet4 48333)
    (:signet 38333)
    (:regtest 18444)
    (:mainnet 8333)))

(defun listen-port (network)
  "The P2P LISTEN port: -port when given, else NETWORK's default (Core
GetListenPort, net.cpp:138-162). Dialing peers keeps the chain default —
Core's -port only moves the listening/advertised side."
  (or *p2p-port-override* (network-port network)))

(defun network-dns-seeds (network)
  "Return the DNS seeds for NETWORK."
  (ecase network
    (:testnet3 bitcoin-lisp.networking:*testnet3-dns-seeds*)
    (:testnet4 bitcoin-lisp.networking:*testnet4-dns-seeds*)
    (:signet bitcoin-lisp.networking:*signet-dns-seeds*)
    (:regtest bitcoin-lisp.networking:*regtest-dns-seeds*)
    (:mainnet bitcoin-lisp.networking:*mainnet-dns-seeds*)))

(defun network-rpc-port (network)
  "Return the default RPC port for NETWORK."
  (ecase network
    (:testnet3 18332)
    (:testnet4 48332)
    (:signet 38332)
    (:regtest 18443)
    (:mainnet 8332)))

(defvar *mainnet-relay-enabled* nil
  "Whether transaction relay is enabled on mainnet. Default NIL for safety.")

(defconstant +max-inbound-peers+ 64
  "Maximum number of inbound peers to keep (Bitcoin Core allows 125 by default;
we cap lower). Excess inbound connections are disconnected at merge time.")

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
  ;; Wallet manager (bitcoin-lisp.rpc:wallet-manager) fanning RPCs out to
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
  ;; The torcontrol client (bitcoin-lisp.networking:tor-controller) keeping
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
  ;; wall-clock (get-universal-time) of the last observed active-chain tip
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
  (bitcoin-lisp.storage:select-current-chainstate (node-chainstates node)))

(defun node-historical-chainstate (node)
  "The chainstate re-deriving history toward a snapshot base block (Core
HistoricalChainstate); NIL when no background validation is in progress."
  (bitcoin-lisp.storage:select-historical-chainstate (node-chainstates node)))

(defun node-validated-chainstate (node)
  "The fully-validated chainstate (Core ValidatedChainstate) — the one
indexes bind to, since they index blocks in order from genesis."
  (bitcoin-lisp.storage:select-validated-chainstate (node-chainstates node)))

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
    (when (and old (null (bitcoin-lisp.storage:chain-state-coins-view chainstate)))
      (setf (bitcoin-lisp.storage:chain-state-coins-view chainstate)
            (bitcoin-lisp.storage:chain-state-coins-view old)))
    (setf (node-chainstates node)
          (if old
              (substitute chainstate old (node-chainstates node))
              (append (node-chainstates node) (list chainstate)))))
  chainstate)

(defun node-utxo-set (node)
  "The current chainstate's coins view — the former utxo-set slot."
  (let ((cs (node-current-chainstate node)))
    (and cs (bitcoin-lisp.storage:chain-state-coins-view cs))))

(defun (setf node-utxo-set) (view node)
  "Set the current chainstate's coins view — the former utxo-set slot."
  (let ((cs (node-current-chainstate node)))
    (unless cs
      (error "Cannot set the node's utxo-set: no current chainstate exists"))
    (setf (bitcoin-lisp.storage:chain-state-coins-view cs) view)))

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
         (h (and cs (bitcoin-lisp.storage:current-height cs))))
    (when (and (integerp h) (> h (node-last-tip-height node)))
      (setf (node-last-tip-height node) h
            (node-last-tip-advance-time node) (get-universal-time)))))

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
                      (max 0 (- (get-universal-time) last))
                      most-positive-fixnum))
         (synced (not bitcoin-lisp.networking::*cached-is-ibd*)))
    (values (health-ok-p alive seconds) seconds synced)))

;;;; Logging (macros and core functions defined in logging.lisp)

(defun show-logs (&key (n 20) (level :debug))
  "Show the last N log entries at or above LEVEL.
LEVEL can be :debug, :info, :warn, or :error."
  (let ((entries '())
        (min-level (log-level-value level)))
    (bt:with-lock-held (*log-buffer-lock*)
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
  (bt:with-lock-held (*log-buffer-lock*)
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

(defun start-file-logging (path)
  "Start logging to a file at PATH."
  (when *log-file-stream*
    (close *log-file-stream*))
  (setf *log-file-stream* (open path :direction :output
                                     :if-exists :append
                                     :if-does-not-exist :create))
  (format t "Logging to file: ~A~%" path)
  path)

(defun stop-file-logging ()
  "Stop logging to file."
  (when *log-file-stream*
    (close *log-file-stream*)
    (setf *log-file-stream* nil))
  t)

;;;; Genesis block headers
;;; Genesis parameters from Bitcoin Core chainparams.cpp

(defun make-genesis-header (network)
  "Construct the genesis block header for NETWORK, taken from the full
genesis-block construction (bitcoin-lisp.storage:make-genesis-block) so the
merkle root is COMPUTED from the real per-network coinbase and the header
hash is verified against the known genesis hash. A previous version shared
mainnet's merkle-root constant across all networks, which was wrong for
testnet4 (its genesis coinbase differs; Core kernel/chainparams.cpp:367-379)."
  (bitcoin-lisp.serialization:bitcoin-block-header
   (bitcoin-lisp.storage:make-genesis-block network)))

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

  ;; Network-aware PoW limit: regtest's trivial limit, the standard limit
  ;; otherwise. derive-target / check-proof-of-work reject targets above it.
  (setf bitcoin-lisp.storage:*pow-limit-target*
        (if (eq network :regtest)
            bitcoin-lisp.storage:+regtest-pow-limit-target+
            bitcoin-lisp.storage:+pow-limit-target+))

  ;; Calculate data path - each network uses its own subdirectory
  (let* ((base-path (pathname data-directory))
         (data-path (ecase network
                      (:testnet3 base-path)
                      (:testnet4 (merge-pathnames "testnet4/" base-path))
                      (:signet (merge-pathnames "signet/" base-path))
                      (:regtest (merge-pathnames "regtest/" base-path))
                      (:mainnet (merge-pathnames "mainnet/" base-path)))))
    ;; Ensure data directory exists
    (ensure-directories-exist (merge-pathnames "dummy" data-path))

    ;; Set network configuration
    (setf bitcoin-lisp.serialization:*network-magic* (network-magic network))
    (setf bitcoin-lisp.networking:*current-port* (network-port network))
    (setf bitcoin-lisp.networking:*dns-seeds* (network-dns-seeds network))

    ;; Create node instance
    (make-node :network network
               :data-directory data-path
               :log-level log-level)))

;;;; Inbound listening

(defun count-inbound-peers (node)
  (count-if #'bitcoin-lisp.networking:peer-inbound (node-peers node)))

(defun merge-inbound-peers (node)
  "Move handshaked inbound peers from the lock-guarded hand-off list into the
node's peer list (capped at +max-inbound-peers+; excess are disconnected). Called
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
          ((< (count-inbound-peers node) +max-inbound-peers+)
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
                     (bitcoin-lisp.networking:peer-address peer))
           (bitcoin-lisp.networking:disconnect-peer peer)))))))

(defun evict-discouraged-inbound (node)
  "If any existing inbound peer is discouraged, disconnect it and return T so a
new inbound connection can take its slot. NIL if none are discouraged."
  (bt:with-recursive-lock-held ((node-lock node))
    (let ((victim (find-if (lambda (p)
                             (and (bitcoin-lisp.networking:peer-inbound p)
                                  (bitcoin-lisp.networking:peer-discouraged-p
                                   (bitcoin-lisp.networking:peer-address p))))
                           (node-peers node))))
      (when victim
        (log-info "Evicting discouraged inbound peer ~A to admit a new connection"
                  (bitcoin-lisp.networking:peer-address victim))
        (setf (node-peers node) (remove victim (node-peers node)))
        (bitcoin-lisp.networking:disconnect-peer victim)
        t))))

(defparameter +inbound-eviction-protect-count+ 4
  "Per protection dimension (lowest ping, longest connected), how many inbound
peers to shield from eviction — the spirit of Bitcoin Core's
AttemptToEvictConnection protected set.")

(defun evict-least-valuable-inbound (node)
  "At inbound capacity with no discouraged peer to drop, evict the least
valuable inbound peer so a new connection can take the slot — stopping an
attacker from filling inbound slots with cheap, sticky connections (the current
behavior was to always drop the newcomer, which never churns toward better
peers). Protects the most valuable inbound peers along two dimensions (lowest
ping latency, longest connected); among the unprotected rest, evicts from the
most-represented /16 netgroup, youngest first. Mirrors the intent of Core's
AttemptToEvictConnection. Returns T if a peer was evicted."
  (bt:with-recursive-lock-held ((node-lock node))
    (let ((inbound (remove-if-not #'bitcoin-lisp.networking:peer-inbound
                                  (node-peers node))))
      (when (cdr inbound)               ; need >1 so something stays protected
        (let* ((by-ping (stable-sort
                         (copy-list inbound) #'<
                         :key (lambda (p)
                                (let ((l (bitcoin-lisp.networking:peer-ping-latency p)))
                                  (if (plusp l) l most-positive-fixnum)))))
               (by-age (stable-sort   ; oldest (smallest connect-time) first
                        (copy-list inbound) #'<
                        :key #'bitcoin-lisp.networking:peer-connect-time))
               (n (min +inbound-eviction-protect-count+ (length inbound)))
               (protected (union (subseq by-ping 0 n) (subseq by-age 0 n)))
               (candidates (remove-if (lambda (p) (member p protected)) inbound)))
          (when candidates
            (let ((groups (make-hash-table :test 'equal)))
              (flet ((grp (p) (or (bitcoin-lisp.networking:ip-netgroup
                                   (bitcoin-lisp.networking:peer-address p))
                                  "_")))
                (dolist (p candidates) (incf (gethash (grp p) groups 0)))
                (let ((victim (first (stable-sort
                                      candidates
                                      (lambda (a b)
                                        (let ((ga (gethash (grp a) groups 0))
                                              (gb (gethash (grp b) groups 0)))
                                          (if (/= ga gb)
                                              (> ga gb)  ; most-populous netgroup first
                                              ;; then youngest (largest connect-time)
                                              (> (bitcoin-lisp.networking:peer-connect-time a)
                                                 (bitcoin-lisp.networking:peer-connect-time b)))))))))
                  (when victim
                    (log-info "Evicting least-valuable inbound peer ~A to admit a new connection"
                              (bitcoin-lisp.networking:peer-address victim))
                    (setf (node-peers node) (remove victim (node-peers node)))
                    (bitcoin-lisp.networking:disconnect-peer victim)
                    t))))))))))

(defun inbound-connection-allowed-p (node host)
  "Admission check for a freshly-accepted inbound connection from HOST,
before any handshake work (Core CConnman::CreateNodeFromAcceptedSocket,
net.cpp:1801-1813): a banned address is always dropped; a discouraged
address is dropped only when the inbound slots are (almost) full. Returns T,
or (VALUES NIL REASON) when the connection must be dropped."
  (cond
    ((bitcoin-lisp.networking:peer-banned-p host)
     (values nil :banned))
    ((and (bitcoin-lisp.networking:peer-discouraged-p host)
          (>= (1+ (bt:with-recursive-lock-held ((node-lock node))
                    (count-inbound-peers node)))
              +max-inbound-peers+))
     (values nil :discouraged))
    (t t)))

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
               (let ((conn (bitcoin-lisp.networking:accept-connection
                            socket :timeout 1)))
                 (when conn
                   ;; Banned/discouraged admission gate BEFORE the handshake
                   ;; (Core drops these in CreateNodeFromAcceptedSocket,
                   ;; net.cpp:1801-1813).
                   (multiple-value-bind (allowed reason)
                       (inbound-connection-allowed-p
                        node (bitcoin-lisp.networking:connection-host conn))
                     (if (not allowed)
                         (progn
                           (log-info "Inbound connection from ~A dropped (~(~A~))"
                                     (bitcoin-lisp.networking:connection-host conn)
                                     reason)
                           (bitcoin-lisp.networking:close-connection conn))
                         (let ((peer (bitcoin-lisp.networking:make-inbound-peer
                                      conn (bitcoin-lisp.networking:connection-host conn)
                                      :inbound-onion onion)))
                           (if (bitcoin-lisp.networking:perform-inbound-handshake peer)
                               (progn
                                 (bitcoin-lisp.networking:send-post-handshake-messages peer)
                                 (bitcoin-lisp.networking:send-compact-block-negotiation peer)
                                 (bt:with-recursive-lock-held ((node-lock node))
                                   (push peer (node-pending-inbound-peers node)))
                                 (log-info "Inbound~:[~; onion~] peer ~A (~A) handshake complete"
                                           onion
                                           (bitcoin-lisp.networking:peer-address peer)
                                           (bitcoin-lisp.networking:peer-user-agent peer)))
                               (bitcoin-lisp.networking:disconnect-peer peer))))))))
             (error (c)
               (log-debug "Inbound accept/handshake error: ~A" c)))))

(defun start-inbound-listener (node bind)
  "Open the listening socket and spawn the accept thread. No-op (logged) if the
port can't be bound."
  (let ((sock (bitcoin-lisp.networking:open-listener bind (listen-port (node-network node)))))
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
         (sock (bitcoin-lisp.networking:open-listener "127.0.0.1" port)))
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
    (bitcoin-lisp.networking:announce-mempool-tx
     (node-peers node) (node-mempool node) txid)))

(defun load-mempool-from-disk
    (node &optional (path (bitcoin-lisp.mempool:mempool-dat-path (node-data-directory node)))
     &key (apply-unbroadcast t))
  "Load a mempool.dat-format file through the normal acceptance path (Core
LoadMempool): prioritisation deltas first (so fee policy sees them), then per-tx
validation against the current UTXO set — stale entries (spent inputs, reorged
context) simply fail and are dropped. Entries are loaded regardless of age (no
expiry filter, unlike Core): mempool-expire prunes old entries on the next block
connection anyway. Residual deltas (txs not in the saved pool) are re-applied
last, then the saved unbroadcast set for txs that made it back into the pool
(Core node/mempool_persist.cpp:134-141) — unless APPLY-UNBROADCAST is NIL,
which is the importmempool RPC's default (Core apply_unbroadcast_set,
rpc/mempool.cpp:1115). PATH defaults to the node's mempool.dat. Returns
(values accepted failed residual-count) on success, or NIL if the file is
missing or corrupt."
  (when (and path (probe-file path))
      (multiple-value-bind (entries residual ok unbroadcast)
          (bitcoin-lisp.mempool:read-mempool-file path)
        (unless ok
          (log-warn "mempool file ~A unreadable or corrupt" path)
          (return-from load-mempool-from-disk nil))
        (let ((mempool (node-mempool node))
              (utxo-set (node-utxo-set node))
              (chain-state (node-chain-state node))
              (accepted 0) (failed 0) (unbroadcast-count 0))
          (dolist (rec entries)
            (destructuring-bind (tx entry-time delta) rec
              (let ((txid (bitcoin-lisp.serialization:transaction-hash tx))
                    (height (bitcoin-lisp.storage:current-height chain-state)))
                (unless (zerop delta)
                  (bitcoin-lisp.mempool:mempool-prioritise mempool txid delta))
                ;; CHAIN-STATE gates the finality/BIP68 checks — a saved tx
                ;; that is no longer minable in the next block must not
                ;; reload (Core LoadMempool goes through the full
                ;; AcceptToMemoryPool, node/mempool_persist.cpp:105).
                (multiple-value-bind (valid error fee replaced sigops)
                    (bitcoin-lisp.validation:validate-transaction-for-mempool
                     tx utxo-set mempool height :chain-state chain-state)
                  (declare (ignore error))
                  (cond
                    (valid
                     (if (eq :ok (bitcoin-lisp.mempool:accept-validated-tx
                                  mempool txid tx fee height
                                  :entry-time entry-time :sigops sigops
                                  :replaced replaced))
                         (incf accepted)
                         (incf failed)))
                    (t (incf failed)))))))
          (dolist (pair residual)
            (bitcoin-lisp.mempool:mempool-prioritise mempool (car pair) (cdr pair)))
          ;; Restore the unbroadcast set for txs that were re-accepted; ids
          ;; whose tx failed to reload are dropped (mempool-add-unbroadcast's
          ;; membership gate) — Core node/mempool_persist.cpp:136-142.
          (when apply-unbroadcast
            (dolist (txid unbroadcast)
              (when (bitcoin-lisp.mempool:mempool-add-unbroadcast mempool txid)
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
  (let ((block (bitcoin-lisp.storage:get-block (node-block-store node) block-hash)))
    (when block
      (let* ((cb (first (bitcoin-lisp.serialization:bitcoin-block-transactions block)))
             (txid (bitcoin-lisp.serialization:transaction-hash cb)))
        (and (bitcoin-lisp.storage:get-utxo
              (bitcoin-lisp.storage:chain-state-coins-view chainstate) txid 0)
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
  (let* ((new-hash (bitcoin-lisp.storage:best-block-hash chain-state))
         (new-height (bitcoin-lisp.storage:current-height chain-state))
         (snapshot-base (bitcoin-lisp.storage:chain-state-from-snapshot-blockhash
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
              (equalp new-hash (bitcoin-lisp.storage::chain-state-genesis-hash
                                chain-state)))
         (let ((view (bitcoin-lisp.storage:chain-state-coins-view chain-state)))
           (when (typep view 'bitcoin-lisp.storage:coins-view-cache)
             (let ((erased (bitcoin-lisp.storage:coins-view-cache-wipe view)))
               (when (plusp erased)
                 (log-info "Chainstate recovery: erased ~D leftover coin~:P from the interrupted wipe"
                           erased)))))
         (bitcoin-lisp.storage:save-state chain-state :in-transition nil)
         (log-warn "Chainstate recovery: interrupted reindex-chainstate; UTXO set reset to empty at genesis (chain will re-sync)")
         t)
        ;; Phase 2 committed the new tip — chainstate.dat already holds it,
        ;; just drop the marker.
        ((committed-p new-hash)
         (bitcoin-lisp.storage:save-state chain-state :in-transition nil)
         (log-info "Chainstate recovery: UTXO set already at recorded tip h=~D; marker cleared"
                   new-height)
         t)
        ;; UTXO set is behind: find the real tip by walking back.
        (t
         (let ((entry (bitcoin-lisp.storage:get-block-index-entry chain-state new-hash)))
           (loop while entry
                 do (setf entry (bitcoin-lisp.storage:block-index-entry-prev-entry entry))
                 until (or (null entry)
                           (committed-p
                            (bitcoin-lisp.storage:block-index-entry-hash entry))))
           (cond
             (entry
              (let ((h (bitcoin-lisp.storage:block-index-entry-height entry))
                    (hash (bitcoin-lisp.storage:block-index-entry-hash entry)))
                ;; pruned-height is left as recorded — pruning is monotone and
                ;; lags the tip by the whole block window, so it is far below
                ;; this rewind point and those files are gone regardless.
                (setf (bitcoin-lisp.storage::chain-state-best-block-hash chain-state) hash
                      (bitcoin-lisp.storage::chain-state-best-height chain-state) h)
                (bitcoin-lisp.storage:save-state chain-state :in-transition nil)
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
        (bitcoin-lisp.networking:request-ibd-stop)
        (loop repeat 600                ; <= 120s; the IBD loops poll the flag
              while (node-syncing node)
              do (sleep 0.2))
        (when (node-syncing node)
          (log-warn "Sync pass did not pause within 120s; proceeding with snapshot activation anyway"))
        (unwind-protect (funcall thunk)
          (bitcoin-lisp.networking:reset-ibd-stop)))
      (funcall thunk)))

(defun %make-snapshot-chainstate (node base-hash)
  "The snapshot chain-state struct for BASE-HASH: status :unvalidated (Core
derives it from from_snapshot_blockhash, validation.cpp:1868 — never
persisted), storage suffix \"_snapshot\", and the block index SHARED with
the primary chainstate (Core keeps it in m_blockman, outside any
chainstate). Used by both activation (create-snapshot-chainstate) and
startup re-detection (load-snapshot-chainstate)."
  (let ((primary (node-current-chainstate node)))
    (bitcoin-lisp.storage:make-chain-state
     :base-path (node-data-directory node)
     :genesis-hash (bitcoin-lisp.storage::chain-state-genesis-hash primary)
     :block-index (bitcoin-lisp.storage::chain-state-block-index primary)
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
    (when (bitcoin-lisp.storage:find-assumeutxo-chainstate-dir
           (node-data-directory node))
      (log-warn "[snapshot] removing stale snapshot chainstate leftovers before activation")
      (bitcoin-lisp.storage:delete-snapshot-chainstate-files
       (node-data-directory node)))
    (bitcoin-lisp.storage:open-chainstate-coins-view snap)
    snap))

(defun abort-snapshot-chainstate (node snap)
  "Tear down SNAP mid-activation (Core cleanup_bad_snapshot): close its coins
DB (releasing the LevelDB lock) and delete its on-disk footprint. Never
signals — this runs on the activation failure path."
  ;; Core's cleanup_bad_snapshot rebalances first (validation.cpp:5697) —
  ;; the failed activation must not leave a split cache allocation behind.
  (ignore-errors (maybe-rebalance-caches node))
  (bitcoin-lisp.storage:close-chainstate-coins-view snap)
  (ignore-errors
    (bitcoin-lisp.storage:delete-snapshot-chainstate-files
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
         (base-hash (bitcoin-lisp.storage:chain-state-from-snapshot-blockhash snap))
         (base-entry (bitcoin-lisp.storage:get-block-index-entry prev base-hash)))
    (assert (eq (bitcoin-lisp.storage:chain-state-assumeutxo-status prev) :validated))
    (assert (null (bitcoin-lisp.storage:chain-state-target-blockhash prev)))
    (assert base-entry)
    (bitcoin-lisp.storage:set-chainstate-target prev base-entry)
    (bt:with-recursive-lock-held ((node-lock node))
      (setf (node-chainstates node)
            (append (node-chainstates node) (list snap))))
    ;; Split the coins-cache budget across the two chainstates (Core calls
    ;; MaybeRebalanceCaches at the end of ActivateSnapshot,
    ;; validation.cpp:5745).
    (maybe-rebalance-caches node)
    (log-info "[snapshot] successfully activated snapshot ~A: current chainstate now at height ~D following the network tip; historical chainstate (h=~D) re-derives history toward the base in the background"
              (bitcoin-lisp.crypto:bytes-to-hex base-hash)
              (bitcoin-lisp.storage:current-height snap)
              (bitcoin-lisp.storage:current-height prev))
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
         (dir (bitcoin-lisp.storage:find-assumeutxo-chainstate-dir data-dir)))
    (when dir
      (let* ((base-hash (bitcoin-lisp.storage:read-snapshot-base-blockhash dir))
             (primary (node-current-chainstate node))
             (base-entry (and base-hash
                              (bitcoin-lisp.storage:get-block-index-entry
                               primary base-hash))))
        (cond
          ((null base-hash)
           (log-warn "[snapshot] snapshot chainstate dir is malformed! no base blockhash file exists at path ~A. Try deleting ~A and calling loadtxoutset again"
                     (namestring (bitcoin-lisp.storage:snapshot-base-blockhash-path dir))
                     (namestring dir))
           nil)
          ((null base-entry)
           ;; Header index lost/regressed below the base. Leave the snapshot
           ;; chainstate on disk and run single-chainstate this boot; once
           ;; headers re-cover the base, the next restart adopts it.
           (log-warn "[snapshot] snapshot base block ~A is not in the header index; not loading the snapshot chainstate this run"
                     (bitcoin-lisp.crypto:bytes-to-hex base-hash))
           nil)
          (t
           (log-info "[snapshot] detected active snapshot chainstate (~A) - loading"
                     (namestring dir))
           (let ((snap (%make-snapshot-chainstate node base-hash))
                 (base-height (bitcoin-lisp.storage:block-index-entry-height base-entry)))
             ;; Tip from chainstate_snapshot.dat; a torn flush defers to the
             ;; per-chainstate recovery pass; a missing .dat means activation
             ;; completed (dir + marker prove the populate did) but the first
             ;; save-state never landed — start the chainstate at its base.
             (case (bitcoin-lisp.storage:load-state snap)
               ((:inconsistent)
                (log-warn "[snapshot] snapshot chainstate in-transition (flush interrupted); will attempt automatic recovery after storage init")
                (push snap *pending-chainstate-recovery*))
               ((t) nil)
               ((nil)
                (log-warn "[snapshot] no chainstate_snapshot.dat; starting the snapshot chainstate at its base (h=~D)" base-height)
                (bitcoin-lisp.storage:update-chain-tip
                 snap (copy-seq base-hash) base-height)))
             ;; The recorded tip must resolve in the shared header index;
             ;; otherwise fall back to the base (blocks above it re-sync).
             (let ((tip-hash (bitcoin-lisp.storage:best-block-hash snap)))
               (unless (and tip-hash
                            (bitcoin-lisp.storage:get-block-index-entry primary tip-hash))
                 (log-warn "[snapshot] snapshot chainstate tip not in the header index; resetting to the base (h=~D)" base-height)
                 (bitcoin-lisp.storage:update-chain-tip
                  snap (copy-seq base-hash) base-height)))
             ;; Open its coins DB (chainstate_snapshot/).
             (bitcoin-lisp.storage:open-chainstate-coins-view snap)
             ;; Retarget the primary (it becomes the historical chainstate)
             ;; and adopt the snapshot chainstate as current.
             (bitcoin-lisp.storage:set-chainstate-target primary base-entry)
             (setf (node-chainstates node)
                   (append (node-chainstates node) (list snap)))
             ;; Split the coins-cache budget across the re-adopted pair (Core
             ;; LoadChainstate's MaybeRebalanceCaches, node/chainstate.cpp:146).
             (maybe-rebalance-caches node)
             (log-info "[snapshot] switching active chainstate to the snapshot chainstate (tip h=~D); historical chainstate at h=~D targets the base at h=~D"
                       (bitcoin-lisp.storage:current-height snap)
                       (bitcoin-lisp.storage:current-height primary)
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

(defvar *shutdown-request* nil
  "NIL, or the pending shutdown request as (REASON . EXIT-CODE). Written
exactly once per run by request-node-shutdown, via CAS rather than a lock so
it is safe to call from a signal handler (a lock could deadlock against the
thread the signal interrupted). One cell, so a reader never sees a reason
without its exit code.")

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
      (unless *shutdown-watchdog-running*
        (bt:make-thread (lambda () (ignore-errors (stop-node)))
                        :name "node-shutdown")))
    registered))

(defun node-shutdown-requested-p ()
  "The reason a shutdown was requested, or NIL (Core ShutdownRequested)."
  (car *shutdown-request*))

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
  (find-if #'bitcoin-lisp.storage:chain-state-from-snapshot-blockhash
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
       (bitcoin-lisp.storage:chain-state-from-snapshot-blockhash snap)
       (eq (bitcoin-lisp.storage:chain-state-assumeutxo-status snap) :unvalidated)
       (eq (bitcoin-lisp.storage:chain-state-assumeutxo-status historical) :validated)
       (bitcoin-lisp.storage:best-block-hash historical)
       (bitcoin-lisp.storage:chain-state-target-blockhash historical)
       (equalp (bitcoin-lisp.storage:chain-state-target-blockhash historical)
               (bitcoin-lisp.storage:chain-state-from-snapshot-blockhash snap))
       ;; ReachedTarget: the historical tip IS the target/base block.
       (equalp (bitcoin-lisp.storage:best-block-hash historical)
               (bitcoin-lisp.storage:chain-state-target-blockhash historical))))

(defun %mark-snapshot-invalid (node historical snap)
  "State mutation Core performs when a snapshot fails validation
(MaybeValidateSnapshot's handle_invalid_snapshot + InvalidateCoinsDBOnDisk,
validation.cpp:6026-6036): reset the historical chainstate's target back to
the network tip, mark the snapshot chainstate :invalid, close its coins DB and
rename its dir aside for forensics. No process shutdown here — the caller
drives that."
  (bitcoin-lisp.storage:set-chainstate-target historical nil)
  (setf (bitcoin-lisp.storage:chain-state-assumeutxo-status snap) :invalid)
  (bitcoin-lisp.storage:close-chainstate-coins-view snap)
  (ignore-errors
    (bitcoin-lisp.storage:rename-snapshot-chainstate-dir-invalid
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
  (let* ((base-hash (bitcoin-lisp.storage:chain-state-target-blockhash historical))
         (au (assumeutxo-data-for-blockhash (node-network node) base-hash)))
    (cond
      ((null au)
       (let ((msg (format nil "assumeutxo data not found for the snapshot base at height ~D — refusing to validate snapshot"
                          (bitcoin-lisp.storage:current-height historical))))
         (log-warn "[snapshot] ~A" msg)
         (%mark-snapshot-invalid node historical snap)
         (values :missing-chainparams msg)))
      (t
       (log-info "[snapshot] computing UTXO stats for the background chainstate to validate the snapshot — this may take a few minutes")
       (let ((got (bitcoin-lisp.storage:compute-utxo-set-hash
                   (bitcoin-lisp.storage:chain-state-coins-view historical)))
             (want (assumeutxo-data-hash-serialized au)))
         (cond
           ((equalp got want)
            (setf (bitcoin-lisp.storage:chain-state-assumeutxo-status snap) :validated
                  (bitcoin-lisp.storage:chain-state-target-utxohash historical) got)
            ;; VALIDATED lifts the snapshot chainstate's prune floor (Core: a
            ;; validated chainstate's GetPruneRange starts at 0 again); the
            ;; prune-walk cursor rewinds so the window the floor protected
            ;; becomes reclaimable.
            (bitcoin-lisp.storage:lift-prune-floor-on-promotion snap historical)
            ;; Core rebalances the caches immediately after promotion
            ;; (validation.cpp:6093): everything to the snapshot chainstate.
            (maybe-rebalance-caches node)
            (log-info "[snapshot] snapshot beginning at ~A has been fully validated"
                      (bitcoin-lisp.crypto:bytes-to-hex
                       (bitcoin-lisp.storage:chain-state-from-snapshot-blockhash snap)))
            (values :success nil))
           (t
            (let ((msg (format nil "failed to validate the -assumeutxo snapshot state: hash mismatch (computed ~A, expected ~A)"
                               (bitcoin-lisp.crypto:bytes-to-hex got)
                               (bitcoin-lisp.crypto:bytes-to-hex want))))
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
                       (bitcoin-lisp.storage:current-height
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
    (unless (and snap (eq (bitcoin-lisp.storage:chain-state-assumeutxo-status snap)
                          :validated))
      (return-from validated-snapshot-cleanup nil))
    ;; ResetChainstates: release every coins DB handle before shuffling dirs.
    (dolist (cs (node-chainstates node))
      (bitcoin-lisp.storage:close-chainstate-coins-view cs))
    ;; Swap chainstate_snapshot/ into chainstate/ and delete the background one.
    (bitcoin-lisp.storage:promote-snapshot-chainstate-files (node-data-directory node))
    ;; Morph the snapshot chainstate struct into the sole primary chainstate:
    ;; drop its snapshot identity (default file names, no target/snapshot
    ;; marking) and reopen its coins view over the now-promoted chainstate/
    ;; LevelDB. Its shared block index and its (snapshot-tip) chain carry over
    ;; intact, so no block re-download is needed.
    (bitcoin-lisp.storage:clear-snapshot-chainstate-identity snap)
    (bitcoin-lisp.storage:open-chainstate-coins-view snap)
    (setf (node-chainstates node) (list snap))
    (log-info "[snapshot] background chainstate consolidated; running as a single fully-validated chainstate at height ~D"
              (bitcoin-lisp.storage:current-height snap))
    t))

(defun %catch-up-blockfilterindex (node)
  "Catch the block-filter index up to the node's validated chainstate tip.
Indexes bind the validated chainstate (Core ValidatedChainstate) and index
blocks in order from genesis — identical to the current chainstate while only
the primary exists, and the promoted snapshot chainstate after assumeutxo
completion. Repairs a best marker left above the tip (e.g. after
invalidateblock), then backfills any shortfall. Shared by startup and the
post-promotion index rebind."
  (let* ((bfi (node-blockfilterindex node))
         (cs (node-validated-chainstate node))
         (tip (bitcoin-lisp.storage:current-height cs)))
    ;; BIP157 genesis-anchor migration: an index built before genesis indexing
    ;; existed seeded its header chain at the first STORED block, so every
    ;; absolute cfheaders/cfcheckpt/getblockfilter header it serves diverges
    ;; from Core and BIP157 light clients ban us. Detect and wipe it here; the
    ;; backfill below then rebuilds the whole index from height 0 (the genesis
    ;; filter is computed from chain parameters). No-op on fresh and healthy
    ;; indexes; on a pruned node a bad index is kept (rebuild impossible) with
    ;; a warning.
    (when (eq :rebuilt (bitcoin-lisp.storage:blockfilterindex-ensure-genesis-anchor bfi cs))
      (log-info "Block filter index wiped; rebuilding from genesis"))
    (when (> (bitcoin-lisp.storage:blockfilterindex-height bfi) tip)
      (log-warn "Block filter index best above tip (~D > ~D); repairing"
                (bitcoin-lisp.storage:blockfilterindex-height bfi) tip)
      (loop for h from tip downto 0
            for e = (bitcoin-lisp.storage:get-block-at-height cs h)
            when (and e (bitcoin-lisp.storage:blockfilterindex-has-block-p
                         bfi (bitcoin-lisp.storage:block-index-entry-hash e)))
              do (bitcoin-lisp.storage:blockfilterindex-set-best
                  bfi h (bitcoin-lisp.storage:block-index-entry-hash e))
                 (return)
            finally (bitcoin-lisp.storage:blockfilterindex-clear-best bfi)))
    (when (< (bitcoin-lisp.storage:blockfilterindex-height bfi) tip)
      (log-info "Building block filter index to height ~D..." tip)
      (let ((n (bitcoin-lisp.storage:build-blockfilterindex
                bfi cs (node-block-store node)
                #'bitcoin-lisp.validation:get-undo-data
                :progress-callback
                (lambda (h pct)
                  (log-info "Block filter index: height ~D (~,1F%)" h pct)))))
        (log-info "Block filter index build complete: ~D block~:P indexed" n)))))

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

(defun %coinstatsindex-fork-height (cs best-hash)
  "The height of the last block common to the active chain and the branch
BEST-HASH sits on (Core walks pprev in Rewind / FindForkInGlobalIndex). NIL
when the header index does not know BEST-HASH — headers are only persisted at
flush time, so the crash that produces a stale marker can also lose the branch
it names — or when the two chains do not actually meet."
  (let* ((stale (bitcoin-lisp.storage:get-block-index-entry cs best-hash))
         (tip (and stale (bitcoin-lisp.storage:get-block-index-entry
                          cs (bitcoin-lisp.storage:best-block-hash cs))))
         (fork (and tip (bitcoin-lisp.validation:find-fork-point stale tip))))
    ;; find-fork-point returns wherever its first walk stopped if the chains
    ;; never meet (a broken prev-entry link), so confirm the answer really is
    ;; on the active chain rather than trusting a fail-open result.
    (when (and fork (bitcoin-lisp.storage:entry-on-active-chain-p cs fork))
      (bitcoin-lisp.storage:block-index-entry-height fork))))

(defun %coinstatsindex-verified-height (node from)
  "The highest height at or below FROM whose stored record provably belongs to
the ACTIVE chain, found by recomputing it from its stored parent and the active
block at that height (see coinstatsindex-record-matches-block-p). This is the
fallback for when the header index cannot resolve the fork point, and it is
what keeps an ordinary unclean shutdown — index a few blocks ahead of the last
flushed tip, same chain — from costing a rebuild from genesis: the record at
the restored tip verifies on the first try. NIL if nothing verifies within
+coinstatsindex-max-rewind+."
  (let ((csi (node-coinstatsindex node))
        (cs (node-validated-chainstate node))
        (store (node-block-store node)))
    (loop for h from from downto (max 0 (- from +coinstatsindex-max-rewind+))
          do (when (zerop h)
               ;; Genesis is on every chain; its record is synthesized, not
               ;; folded from a parent, so presence is the whole check.
               (return (and (bitcoin-lisp.storage:coinstatsindex-get-stats csi 0) 0)))
             (let* ((entry (bitcoin-lisp.storage:get-block-at-height cs h))
                    (hash (and entry (bitcoin-lisp.storage:block-index-entry-hash entry)))
                    (block (and hash (bitcoin-lisp.storage:get-block store hash))))
               (when (and block
                          (bitcoin-lisp.storage:coinstatsindex-record-matches-block-p
                           csi block hash h
                           (bitcoin-lisp.validation:get-undo-data hash)
                           (bitcoin-lisp.validation:calculate-block-subsidy h)))
                 (return h))))))

(defun %rewind-coinstatsindex (node)
  "Make the coinstats index's best marker name a block on the ACTIVE chain
before anything backfills on top of it, moving it back to the last common
ancestor when it does not (Core BaseIndex::Rewind). Records above the new best
are then rewritten by the backfill.

Returns NIL when the index was already consistent — the common case, and it
costs one hash comparison: a rewind that always rebuilt would be a severe
performance regression. Otherwise returns the height rewound to, or -1 when no
trustworthy record could be identified and the index must be rebuilt."
  (let* ((csi (node-coinstatsindex node))
         (cs (node-validated-chainstate node))
         (tip (bitcoin-lisp.storage:current-height cs)))
    (multiple-value-bind (best-height best-hash)
        (bitcoin-lisp.storage:coinstatsindex-best csi)
      (when (minusp best-height)
        (return-from %rewind-coinstatsindex nil))
      (let ((active (and (<= best-height tip)
                         (bitcoin-lisp.storage:get-block-at-height cs best-height))))
        (when (and active best-hash
                   (equalp (bitcoin-lisp.storage:block-index-entry-hash active) best-hash))
          (return-from %rewind-coinstatsindex nil)))
      (log-warn "Coinstats index best (height ~D, ~A) is not on the active chain (tip ~D); rewinding"
                best-height
                (if best-hash (bitcoin-lisp.crypto:bytes-to-hex best-hash) "no hash")
                tip)
      (let* ((fork (and best-hash (%coinstatsindex-fork-height cs best-hash)))
             (target (or (and fork
                              (<= fork tip)
                              (bitcoin-lisp.storage:coinstatsindex-get-stats csi fork)
                              fork)
                         (%coinstatsindex-verified-height node (min best-height tip))))
             (entry (and target (bitcoin-lisp.storage:get-block-at-height cs target))))
        (cond
          (entry
           (log-warn "Coinstats index rewound to height ~D (~A records above it will be rebuilt)"
                     target (- tip target))
           (bitcoin-lisp.storage:coinstatsindex-set-best
            csi target (bitcoin-lisp.storage:block-index-entry-hash entry))
           target)
          (t
           (log-warn "Coinstats index: no record below height ~D could be tied to the active chain; rebuilding from genesis"
                     (min best-height tip))
           (bitcoin-lisp.storage:coinstatsindex-clear-best csi)
           -1))))))

(defun %catch-up-coinstatsindex (node)
  "Catch the coinstats index up to the node's validated chainstate tip. Its
running MuHash must be contiguous from genesis, so a pruned node (missing
early undo data) can only build it if its stored history reaches genesis —
otherwise the backfill stops at the first gap. Rewinds a best marker that is
not on the active chain (including one left above the tip) before backfilling.
Shared by startup and the post-promotion index rebind."
  (let* ((csi (node-coinstatsindex node))
         (cs (node-validated-chainstate node))
         (tip (bitcoin-lisp.storage:current-height cs)))
    (%rewind-coinstatsindex node)
    (when (< (bitcoin-lisp.storage:coinstatsindex-height csi) tip)
      (log-info "Building coinstats index to height ~D..." tip)
      (let ((n (bitcoin-lisp.storage:build-coinstatsindex
                csi cs (node-block-store node)
                #'bitcoin-lisp.validation:get-undo-data
                #'bitcoin-lisp.validation:calculate-block-subsidy
                :progress-callback
                (lambda (h pct)
                  (log-info "Coinstats index: height ~D (~,1F%)" h pct)))))
        (log-info "Coinstats index build complete: ~D block~:P indexed" n)
        (when (< (bitcoin-lisp.storage:coinstatsindex-height csi) tip)
          (log-warn "Coinstats index stopped at height ~D of ~D (missing block/undo ~
data below the pruned horizon; the index needs genesis-contiguous history)"
                    (bitcoin-lisp.storage:coinstatsindex-height csi) tip))))))

(defun restart-indexes-for-validated-chainstate (node)
  "Rebind the block-filter and coinstats indexes onto the node's (now
promoted) validated chainstate and catch them up to its tip (Core restarts
all indexes on background-sync completion, init.cpp:1367-1383). During the
background sync the indexes tracked the historical chainstate up to the
snapshot base; the promoted chainstate carries the full chain past the base,
so this resumes indexing from where each index left off. A no-op when no
index is enabled."
  (when (node-blockfilterindex node) (%catch-up-blockfilterindex node))
  (when (node-coinstatsindex node) (%catch-up-coinstatsindex node)))

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
            (bitcoin-lisp.networking:save-address-book
             (node-address-book node)
             (bitcoin-lisp.networking:peers-dat-path (node-data-directory node)))
            (log-debug "Periodic peers.dat dump (~D entries)"
                       (bitcoin-lisp.networking:address-book-count
                        (node-address-book node))))
        (error (e)
          (log-warn "Periodic peers.dat dump failed: ~A" e)))
      t)))

(defun start-node (&key (data-directory "~/.bitcoin-lisp/")
                        (network :testnet3)
                        (log-level :info)
                        (log-file nil)
                        (console-log t)
                        (max-peers 8)
                        (sync t)
                        (txindex nil)
                        (blockfilterindex nil)
                        (prune nil)
                        (rpc-port nil)
                        (rpc-bind "127.0.0.1")
                        (rpc-user nil)
                        (rpc-password nil)
                        (listen t)
                        (listen-bind "0.0.0.0")
                        (listen-onion t)
                        (tor-control nil)
                        (tor-password nil)
                        (dbcache-mib nil)
                        (v2transport nil)
                        (coinstatsindex nil)
                        (reindex-chainstate nil)
                        (force-compact-db nil)
                        (peer-block-filters nil)
                        (tx-reconciliation nil)
                        (webui nil webui-supplied-p)
                        (webui-path nil)
                        (webui-open nil)
                        (wallet nil wallet-supplied-p)
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
MAX-PEERS: Maximum number of peer connections
SYNC: If T, start syncing immediately
TXINDEX: If T, enable transaction index for getrawtransaction lookups
BLOCKFILTERINDEX: If T, enable the BIP158 basic block filter index (getblockfilter,
  scanblocks, getdescriptoractivity)
PRUNE: Block pruning target in MiB (nil=off, 1=manual-only, >=550=automatic)
RPC-PORT: Port for RPC server (nil = no RPC, default 18332 testnet / 8332 mainnet)
RPC-BIND: Address to bind RPC server (default 127.0.0.1)
RPC-USER: RPC authentication username (nil = no auth)
RPC-PASSWORD: RPC authentication password
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

  (setf *node-start-time* (bitcoin-lisp.serialization:get-unix-time))

  ;; Wire up logging BEFORE init-node so its log-info calls go somewhere.
  ;; Without these, the node runs silently — the May 5 restart had this
  ;; failure mode (no node.log entries since May 2 16:32 crash).
  (when console-log
    (enable-console-logging))
  (when log-file
    (start-file-logging log-file))

  ;; UTXO cache budget (Core -dbcache). Larger = fewer LevelDB disk reads.
  (when dbcache-mib
    (unless (and (integerp dbcache-mib) (>= dbcache-mib 4))
      (error "Invalid dbcache-mib: ~A. Must be an integer >= 4." dbcache-mib))
    (setf *coins-cache-budget-bytes* (* dbcache-mib 1024 1024))
    (log-info "UTXO coins-cache budget: ~D MiB" dbcache-mib))

  ;; Validate the pruning configuration BEFORE assigning the global — a
  ;; config-validation error must not leave *prune-target-mib* set (a failed
  ;; start-node previously leaked the half-applied prune setting into the
  ;; process, making e.g. a later loadtxoutset believe the node is pruned).
  (when prune
    (unless (or (= prune 1) (>= prune 550))
      (error "Invalid prune target: ~A MiB. Must be 1 (manual-only) or >= 550." prune))
    (when (and prune txindex)
      (error "Cannot enable both pruning and txindex. Pruned blocks cannot be looked up."))
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
  (dolist (spec bitcoin-lisp.networking:*external-ips*)
    (unless (bitcoin-lisp.networking:parse-network-address spec)
      (error "Cannot resolve -externalip address: '~A'" spec)))

  ;; Initialize node
  (setf *node* (init-node data-directory :network network :log-level log-level))
  (setf (node-max-peers *node*) max-peers)
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
  ;; -stopatheight: re-arm the once-only shutdown trigger for this run.
  (setf *stop-at-height-triggered* nil
        *disk-space-abort-triggered* nil)
  ;; Re-arm the shutdown coordination latches: a previous run in the same
  ;; image (tests, an in-REPL restart) leaves them set, and a pre-set
  ;; *shutdown-request* would make the watchdog stop this run immediately.
  (setf *shutdown-request* nil
        *shutdown-complete* nil
        *stop-node-in-progress* nil)
  ;; Periodic peers.dat dump baseline (first dump 15 min from now).
  (setf *last-peers-dump-time* (get-universal-time))
  (setf *current-log-level* log-level)
  (log-info "Bitcoin-Lisp Node v0.1.0")
  (log-info "Network: ~A" network)
  (log-info "Data directory: ~A" (node-data-directory *node*))

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
        (list (bitcoin-lisp.storage:init-chain-state (node-data-directory *node*))))

  ;; Genesis block index entry is ensured after load-header-index below

  (setf *pending-chainstate-recovery* nil)
  (let ((load-result (bitcoin-lisp.storage:load-state (node-chain-state *node*))))
    (case load-result
      ((:inconsistent)
       ;; A flush was interrupted mid-commit. Don't abort — defer recovery
       ;; until the block store, UTXO cache, and header index are open
       ;; (recover-inconsistent-chainstate needs all three).
       (log-warn "Chainstate in-transition (flush interrupted); will attempt automatic recovery after storage init")
       (push (node-chain-state *node*) *pending-chainstate-recovery*))
      ((t)
       (log-info "Loaded existing chain state: height ~D"
                 (bitcoin-lisp.storage:current-height (node-chain-state *node*))))
      ((nil) nil)))

  ;; Initialize block store
  (log-info "Initializing block storage...")
  (setf (node-block-store *node*)
        (bitcoin-lisp.storage:init-block-store (node-data-directory *node*)))

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
                           (bitcoin-lisp.storage:chainstate-leveldb-path primary)))
         (utxoset-dat (bitcoin-lisp.storage:utxo-set-file-path data-dir))
         (migrated-p (bitcoin-lisp.storage:leveldb-utxo-migration-complete-p
                      chainstate-path)))
    (when (and (not migrated-p) (probe-file utxoset-dat))
      (log-info "Found legacy utxoset.dat; migrating into LevelDB at ~A ..."
                chainstate-path)
      (bitcoin-lisp.storage:migrate-utxoset-dat-to-leveldb
       utxoset-dat chainstate-path)
      (log-info "Migration complete; LevelDB is now the canonical UTXO store"))
    (let ((view (bitcoin-lisp.storage:open-coins-view-db chainstate-path)))
      (setf (bitcoin-lisp.storage:chain-state-coins-view primary)
            (bitcoin-lisp.storage:make-coins-view-cache view))
      (log-info "UTXO cache opened (base: ~A)" chainstate-path)))

  ;; Load persisted header index if available
  (when (bitcoin-lisp.storage:load-header-index (node-chain-state *node*))
    (log-info "Loaded persisted header index: ~D entries"
              (hash-table-count
               (bitcoin-lisp.storage::chain-state-block-index
                (node-chain-state *node*)))))

  ;; Ensure genesis block is in the index with a proper header
  ;; (needed for difficulty walk-back on testnet)
  (let* ((genesis-hash (bitcoin-lisp.storage:network-genesis-hash network))
         (genesis-entry (bitcoin-lisp.storage:get-block-index-entry
                         (node-chain-state *node*) genesis-hash))
         (genesis-header (make-genesis-header network)))
    (if genesis-entry
        ;; Fix existing entry if it has a missing or zeroed header, or a
        ;; persisted header with the wrong merkle root (the old shared-constant
        ;; make-genesis-header gave testnet4 mainnet's merkle root, and header
        ;; indexes saved before the fix still carry it).
        (let ((h (bitcoin-lisp.storage:block-index-entry-header genesis-entry)))
          (when (or (null h)
                    (zerop (bitcoin-lisp.serialization:block-header-bits h))
                    (not (equalp (bitcoin-lisp.serialization:block-header-merkle-root h)
                                 (bitcoin-lisp.serialization:block-header-merkle-root
                                  genesis-header))))
            (setf (bitcoin-lisp.storage:block-index-entry-header genesis-entry)
                  genesis-header)))
        ;; Create new genesis entry
        (bitcoin-lisp.storage:add-block-index-entry
         (node-chain-state *node*)
         (bitcoin-lisp.storage:make-block-index-entry
          :hash genesis-hash
          :height 0
          :header genesis-header
          :prev-entry nil
          :chain-work 0
          :status :valid
          :tx-count 1))))   ; genesis carries exactly its coinbase

  ;; Snapshot chainstate startup handling (Core LoadChainstate ordering,
  ;; node/chainstate.cpp:151-238). -reindex-chainstate deletes a snapshot
  ;; chainstate outright (Core wipe_chainstate_db) — the primary then
  ;; rebuilds from stored blocks with no target. Otherwise, detect a
  ;; persisted snapshot chainstate dir and re-init dual chainstates. Runs
  ;; after the header index is loaded (the base entry must resolve) and
  ;; before crash-recovery resolution below (a torn snapshot flush joins the
  ;; pending-recovery list).
  (if reindex-chainstate
      (when (bitcoin-lisp.storage:find-assumeutxo-chainstate-dir
             (node-data-directory *node*))
        (log-info "[snapshot] deleting snapshot chainstate due to reindexing")
        (bitcoin-lisp.storage:delete-snapshot-chainstate-files
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
  (let ((undo-path (merge-pathnames "undo/" (node-data-directory *node*))))
    (bitcoin-lisp.validation:initialize-undo-storage undo-path)
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
    (let ((swept (bitcoin-lisp.validation:prune-stale-undo-files
                  (node-chain-state *node*)
                  :horizon (reduce #'min (node-chainstates *node*)
                                   :key #'bitcoin-lisp.storage:chain-state-pruned-height))))
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
  (setf (node-mempool *node*) (bitcoin-lisp.mempool:make-mempool))

  ;; Initialize fee estimator
  (log-info "Initializing fee estimator...")
  (setf (node-fee-estimator *node*)
        (bitcoin-lisp.mempool:make-fee-estimator
         :data-directory (node-data-directory *node*)))
  ;; Load persisted fee stats
  (bitcoin-lisp.mempool:load-fee-stats (node-fee-estimator *node*))

  ;; Reload the persisted mempool through normal acceptance (Core LoadMempool)
  (load-mempool-from-disk *node*)

  ;; Initialize peer address book
  (log-info "Loading peer address book...")
  (setf (node-address-book *node*) (bitcoin-lisp.networking:make-address-book))
  (let ((peers-path (bitcoin-lisp.networking:peers-dat-path (node-data-directory *node*))))
    (when (bitcoin-lisp.networking:load-address-book (node-address-book *node*) peers-path)
      (log-info "Loaded peer address book: ~D entries"
                (bitcoin-lisp.networking:address-book-count (node-address-book *node*)))))

  ;; Manual banlist persistence (Core BanMan <datadir>/banlist.json): load
  ;; previous bans (expired entries swept) and point future mutations at the
  ;; file — every setban/clearbanned dumps it immediately, like Core.
  (setf bitcoin-lisp.networking:*banlist-path*
        (merge-pathnames "banlist.json" (node-data-directory *node*)))
  (let ((n (bitcoin-lisp.networking:load-banlist)))
    (when (and n (plusp n))
      (log-info "Loaded ~D banned address~:P from banlist.json" n)))

  ;; Load reconnection anchors (tried first, before DNS seeds — anti-eclipse).
  (load-anchors *node*)

  ;; Initialize transaction index (optional)
  (when txindex
    (log-info "Initializing transaction index...")
    (setf (node-tx-index *node*)
          (bitcoin-lisp.storage:init-tx-index (node-data-directory *node*)
                                               :enabled t))
    (log-info "Transaction index loaded: ~D entries"
              (bitcoin-lisp.storage:txindex-count (node-tx-index *node*))))

  ;; Initialize BIP158 block filter index (optional)
  (when blockfilterindex
    (log-info "Initializing block filter index...")
    (setf *blockfilterindex-stall-logged* nil)
    (setf (node-blockfilterindex *node*)
          (bitcoin-lisp.storage:init-blockfilterindex (node-data-directory *node*)
                                                       :enabled t))
    (log-info "Block filter index loaded: indexed to height ~D"
              (bitcoin-lisp.storage:blockfilterindex-height (node-blockfilterindex *node*)))
    ;; One-time catch-up over already-stored blocks, before the sync thread
    ;; starts (single-threaded here, so no writer races). Fresh-from-genesis
    ;; nodes have nothing to do; the connect-time hook then indexes forward.
    (%catch-up-blockfilterindex *node*))

  ;; Initialize coinstatsindex (optional). Like the filter index, catch up over
  ;; already-stored blocks before the sync thread starts, then the connect-time
  ;; hook advances it. Its running MuHash must be contiguous from genesis, so a
  ;; pruned node (missing early undo data) can only build it if its stored
  ;; history reaches genesis -- otherwise the backfill stops at the first gap.
  (when coinstatsindex
    (log-info "Initializing coinstats index...")
    (setf (node-coinstatsindex *node*)
          (bitcoin-lisp.storage:init-coinstatsindex (node-data-directory *node*)
                                                    :enabled t))
    (log-info "Coinstats index loaded: indexed to height ~D"
              (bitcoin-lisp.storage:coinstatsindex-height (node-coinstatsindex *node*)))
    ;; A chainstate reindex may have changed UTXO-set contents (e.g. dropping
    ;; unspendable outputs), so the coinstats records must be rebuilt to stay
    ;; consistent. Clear the best marker to force a full rebuild below.
    (when reindex-chainstate
      (bitcoin-lisp.storage:coinstatsindex-clear-best (node-coinstatsindex *node*))
      (log-info "Coinstats index: rebuilding after chainstate reindex"))
    (%catch-up-coinstatsindex *node*))

  ;; -forcecompactdb: once every LevelDB is open (and any reindex/backfill has
  ;; run), full-compact them to reclaim tombstone space -- e.g. the ~24M delete
  ;; markers a reindex-chainstate wipe leaves behind. Bitcoin Core does the same
  ;; via CDBWrapper force_compact when -forcecompactdb is set.
  (when force-compact-db
    (force-compact-databases))

  ;; BIP157 filter serving (-peerblockfilters): gated above on the block filter
  ;; index being enabled; advertised as NODE_COMPACT_FILTERS in our version.
  (setf bitcoin-lisp:*peer-block-filters* (and peer-block-filters t))
  (when peer-block-filters
    (log-info "BIP157 compact filter serving enabled (NODE_COMPACT_FILTERS)"))

  ;; BIP330 Erlay handshake (-txreconciliation; Core DEBUG_ONLY, default off).
  ;; Negotiates sendtxrcncl + per-peer salt storage only — no sketch exchange
  ;; exists at Core ref d3056bc either.
  (setf bitcoin-lisp:*tx-reconciliation* (and tx-reconciliation t))
  (when tx-reconciliation
    (log-info "BIP330 transaction reconciliation handshake enabled (sendtxrcncl)"))

  ;; BIP324 v2 transport opt-in. Effective only if libsecp256k1 has the
  ;; ellswift module (probed lazily per connection via v2-available-p).
  (setf bitcoin-lisp.networking:*v2-transport-enabled* (and v2transport t))
  (when v2transport
    (log-info "BIP324 v2 transport enabled (~:[ellswift NOT available -- will run v1 only~;active~])"
              (bitcoin-lisp.networking:v2-available-p)))

  ;; Initialize secp256k1
  (log-info "Initializing cryptographic context...")
  (bitcoin-lisp.crypto:ensure-secp256k1-loaded)

  ;; Wallet support (wallet P1). Default: enabled everywhere except mainnet,
  ;; where holding keys on an internet-facing node is the operator's explicit
  ;; opt-in (-wallet), mirroring the relay/-webui safety pattern.
  (let ((wallet-enabled (if wallet-supplied-p
                            (and wallet t)
                            (not (eq network :mainnet)))))
    (when wallet-enabled
      (setf (node-wallet-manager *node*)
            (bitcoin-lisp.rpc:init-wallet-manager (node-data-directory *node*)
                                                  network))
      (log-info "Wallet support enabled (descriptor wallets under ~A)"
                (merge-pathnames "wallets/" (node-data-directory *node*)))
      ;; Core LoadWallets (load.cpp:118): load every wallet recorded for
      ;; startup in settings.json. Runs here because the chainstate (above)
      ;; and the mempool (load-mempool-from-disk) are both up, so each wallet
      ;; can catch up from its locator and fold in the mempool; networking has
      ;; not started, so no block can connect underneath the catch-up.
      (bitcoin-lisp.rpc:load-wallets-on-startup *node*)))

  (setf (node-running *node*) t)

  ;; Start RPC server if port specified
  (when rpc-port
    ;; Web UI default (gui-plan §2): on everywhere except mainnet, where
    ;; enabling it is the operator's explicit choice (-webui).
    (let* ((webui-enabled (if webui-supplied-p
                              (and webui t)
                              (not (eq network :mainnet))))
           (server (bitcoin-lisp.rpc:start-rpc-server *node*
                                                      :port rpc-port
                                                      :bind rpc-bind
                                                      :user rpc-user
                                                      :password rpc-password
                                                      :rest-enabled rest-enabled
                                                      :ui-enabled webui-enabled
                                                      :ui-directory webui-path)))
      ;; -webuiopen: pop the local browser at the dashboard. Logged, never
      ;; fatal (open-browser-to-ui catches everything).
      (when (and server webui-enabled webui-open)
        (bitcoin-lisp.rpc:open-browser-to-ui rpc-port))))

  ;; Connect to peers and sync if requested (in background thread)
  ;; Reconnects and retries when peers are lost, similar to Bitcoin Core's
  ;; CheckForStaleTipAndEvictPeers (net_processing.cpp:5460)
  (when sync
    (bitcoin-lisp.networking:reset-ibd-stop)
    (bitcoin-lisp.networking:reset-tx-requests)
    (bitcoin-lisp.networking:reset-initial-broadcast-schedule)
    ;; Fresh recent-confirmed filter (Core builds it per process; covers
    ;; in-image restarts).
    (bitcoin-lisp.validation:reset-recent-confirmed)
    ;; Seed the durable at-tip liveness signal (item #6) so a freshly-started,
    ;; already-at-tip node reports healthy on /rest/health before its first new
    ;; block. last-tip-height starts at the current tip so only genuine advances
    ;; bump the timestamp.
    (let ((cs (node-current-chainstate *node*)))
      (setf (node-last-tip-advance-time *node*) (get-universal-time)
            (node-last-tip-height *node*)
            (if cs (bitcoin-lisp.storage:current-height cs) 0)))
    (setf (node-sync-thread *node*)
          (bt:make-thread
           (lambda ()
             (handler-case
                 (progn
                   ;; Initial connection. Guarded on its own so a startup dial
                   ;; failure logs and defers to the loop's reconnect path
                   ;; instead of ending the thread (a dead sync thread with
                   ;; node-running still T is a socket-reading zombie).
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
                               (loop repeat 30 while (node-running *node*)
                                     do (sleep 1)
                                        ;; Retry buffered unsent bytes on
                                        ;; every peer (non-blocking) — the
                                        ;; periodic half of Core's
                                        ;; SocketSendData.
                                        (bitcoin-lisp.networking:flush-peer-send-buffers
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
                                               (pump (bitcoin-lisp.networking:pump-peer-messages
                                                      (node-peers *node*)
                                                      cs
                                                      (bitcoin-lisp.storage:chain-state-coins-view cs)
                                                      (node-block-store *node*)
                                                      :mempool (node-mempool *node*)
                                                      :address-book (node-address-book *node*)
                                                      :fee-estimator (node-fee-estimator *node*)
                                                      :recent-rejects (node-recent-rejects *node*))))
                                          ;; Tx-request scheduler: send
                                          ;; delayed announcements now due,
                                          ;; and re-route requests that
                                          ;; expired (60s) to another
                                          ;; announcer (Core GetRequestsToSend
                                          ;; runs per SendMessages pass).
                                          (bitcoin-lisp.networking:process-tx-requests)
                                          (bitcoin-lisp.networking:retry-timed-out-tx-requests)
                                          ;; Trickled tx announcements: drain
                                          ;; due per-peer inv queues each
                                          ;; second (Poisson schedules inside;
                                          ;; Core SendMessages runs its
                                          ;; equivalent on every message pump).
                                          (bitcoin-lisp.networking:flush-tx-announcements
                                           (node-peers *node*)
                                           (node-mempool *node*))
                                          ;; Locally-submitted txs still in the
                                          ;; unbroadcast set get re-announced
                                          ;; every 10-15 min until a peer's
                                          ;; getdata confirms propagation (Core
                                          ;; ReattemptInitialBroadcast).
                                          (bitcoin-lisp.networking:maybe-reattempt-initial-broadcast
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
                                          (bitcoin-lisp.rpc:wallets-maybe-resend *node*)
                                          ;; Local-address self-advertisement
                                          ;; (our onion address, once torcontrol
                                          ;; registers it): per-peer ~24h Poisson
                                          ;; schedule inside, no-op while the
                                          ;; local-address map is empty or in
                                          ;; IBD (Core MaybeSendAddr).
                                          (bitcoin-lisp.networking:maybe-advertise-local-address
                                           (node-peers *node*)
                                           (node-chain-state *node*))
                                          ;; New headers announced: start the
                                          ;; next sync cycle now to fetch the
                                          ;; block instead of waiting out the
                                          ;; 30s poll.
                                          ;; Record a tip advance observed this
                                          ;; second (item #6 durable liveness).
                                          (note-node-tip-progress *node*)
                                          (when (plusp (bitcoin-lisp.networking:ibd-context-headers-received pump))
                                            (return)))))
                              (t
                               (log-warn "No peers available, reconnecting in 5s...")
                               (loop repeat 5 while (node-running *node*)
                                     do (sleep 1))
                               (connect-to-peers *node* max-peers
                                                 :timeout 30 :min-peers 1))))
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
    (bitcoin-lisp.networking:clear-local-addresses)
    (start-onion-listener *node*)
    (setf (node-tor-controller *node*)
          (bitcoin-lisp.networking:start-tor-control
           :control-spec tor-control
           :password tor-password
           :data-directory (node-data-directory *node*)
           :virtual-port (network-port network)
           :target-port (onion-listen-port *node*))))

  ;; -externalip: advertise the given addresses as our own (Core
  ;; init.cpp:1803-1808: AddLocal(addr, LOCAL_MANUAL) at the listen port).
  ;; Validated resolvable above; runs after the tor block so its
  ;; clear-local-addresses cannot wipe these entries.
  (dolist (spec bitcoin-lisp.networking:*external-ips*)
    (multiple-value-bind (net bytes)
        (bitcoin-lisp.networking:parse-network-address spec)
      (when net
        (bitcoin-lisp.networking:add-local
         net bytes (listen-port network)
         bitcoin-lisp.networking:+local-manual+))))

  (install-shutdown-handler)
  (log-info "Node started successfully")
  *node*)

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
         (datadir (or (cdr (assoc "datadir" cli :test #'string=)) "~/.bitcoin-lisp/"))
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
         (conf-text (when (probe-file conf-path)
                      (log-info "Reading config file ~A" conf-path)
                      (alexandria:read-file-into-string conf-path))))
    (multiple-value-bind (plist merged) (args->start-node-plist args conf-text)
      ;; Unknown CONFIG-FILE keys only warn (Core ReadConfigFiles with
      ;; ignore_invalid_keys=true, common/init.cpp:38: "Ignoring unknown
      ;; configuration value") — unlike unknown CLI options, which error.
      (when conf-text
        (dolist (k (unknown-config-file-keys
                    (parse-bitcoin-conf conf-text)))
          (log-warn "Ignoring unknown configuration value ~A" k)))
      ;; Apply the process-global config specials (options with no start-node
      ;; keyword) from the same merged config, before launching.
      (apply-config-globals merged)
      ;; datadir only comes from the CLI/default (locating the conf needs it), so
      ;; make sure it reaches start-node even if it wasn't in the spec scan.
      (unless (getf plist :data-directory)
        (setf (getf plist :data-directory) datadir))
      (apply #'start-node plist))))

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

(defun chainstate-coins-cache-budget (chainstate)
  "CHAINSTATE's coins-cache budget in bytes: its per-chainstate allocation
when maybe-rebalance-caches has split the global budget (assumeutxo dual
chainstates), otherwise the whole *coins-cache-budget-bytes*."
  (or (bitcoin-lisp.storage:chain-state-coins-cache-bytes chainstate)
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
                  (bitcoin-lisp.storage:chain-state-from-snapshot-blockhash current))
         (log-info "[snapshot] allocating all cache to the snapshot chainstate"))
       (when current
         (setf (bitcoin-lisp.storage:chain-state-coins-cache-bytes current) nil)))
      (t
       (let ((total *coins-cache-budget-bytes*))
         (multiple-value-bind (current-share historical-share)
             (if (bitcoin-lisp.networking:initial-block-download-p current)
                 (values 0.95d0 0.05d0)
                 (values 0.05d0 0.95d0))
           (setf (bitcoin-lisp.storage:chain-state-coins-cache-bytes current)
                 (floor (* total current-share))
                 (bitcoin-lisp.storage:chain-state-coins-cache-bytes historical)
                 (floor (* total historical-share)))
           (log-info "[snapshot] coins-cache budgets rebalanced: current chainstate ~D MiB, historical chainstate ~D MiB"
                     (floor (chainstate-coins-cache-budget current) 1048576)
                     (floor (chainstate-coins-cache-budget historical) 1048576))))))))

(defun rebalance-caches-on-ibd-exit ()
  "Rebalance the coins-cache allocation when the node leaves initial block
download while a background (historical) chainstate is in use (Core
ActivateBestChain's exited_ibd hook, validation.cpp:3479-3486). Called from
the IBD latch flip in bitcoin-lisp.networking:initial-block-download-p."
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
  "Wall-clock time (get-universal-time) of the last successful periodic
   flush. Used by the time-based trigger.")

(defun log-memory-snapshot (label)
  "Log a snapshot of the major in-memory caches plus SBCL heap usage.
Used to diagnose memory growth — call before/after flush so we can
correlate cache sizes with the heap watermark.

The May 5 OOM at h=72814 had heap at 8.55 GB but the explainable
state (UTXO 600MB + headers 30MB + sig-cache 5MB + queues 80MB) only
accounts for ~700 MB. This logger surfaces the gap."
  #+sbcl
  (let* ((utxo-count (and (node-utxo-set *node*)
                          (bitcoin-lisp.storage:utxo-count
                           (node-utxo-set *node*))))
         (coins-cache-mb (and (node-utxo-set *node*)
                              (/ (bitcoin-lisp.storage:view-mem-bytes
                                  (node-utxo-set *node*))
                                 1048576.0)))
         (header-count (and (node-chain-state *node*)
                            (hash-table-count
                             (bitcoin-lisp.storage::chain-state-block-index
                              (node-chain-state *node*)))))
         (sig-cache-count
           (+ (hash-table-count bitcoin-lisp.coalton.interop:*signature-cache*)
              (hash-table-count bitcoin-lisp.coalton.interop:*signature-cache-prev*)))
         (ibd-pending
           (and bitcoin-lisp.networking::*ibd-context*
                (hash-table-count
                 (bitcoin-lisp.networking::ibd-context-pending-blocks
                  bitcoin-lisp.networking::*ibd-context*))))
         (ibd-queue
           (and bitcoin-lisp.networking::*ibd-context*
                (hash-table-count
                 (bitcoin-lisp.networking::ibd-context-block-queue
                  bitcoin-lisp.networking::*ibd-context*))))
         (ibd-in-flight
           (and bitcoin-lisp.networking::*ibd-context*
                (hash-table-count
                 (bitcoin-lisp.networking::ibd-context-in-flight
                  bitcoin-lisp.networking::*ibd-context*))))
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

(defun %flush-chainstate (chainstate &key (label "Periodic"))
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
          (bitcoin-lisp.storage:save-state chainstate :in-transition t)
          (bitcoin-lisp.storage:save-header-index chainstate))
        (when *flush-mid-commit-hook*
          (funcall *flush-mid-commit-hook* chainstate))
        ;; Phase 2: flush cache → LevelDB. Per-flush work is proportional
        ;; to dirty entries (typically a few thousand at the tip), not
        ;; the full ~17M-entry set — replaces the ~13s utxoset.dat
        ;; rewrite that previously froze the sync thread.
        (let ((view (and chainstate
                         (bitcoin-lisp.storage:chain-state-coins-view chainstate))))
          (when (typep view 'bitcoin-lisp.storage:coins-view-cache)
            ;; :sync t fdatasyncs the LevelDB writebatch before we proceed, so a
            ;; power loss after Phase 3 clears the marker cannot leave the coins
            ;; un-durable while chainstate.dat says they are committed. (Was
            ;; :sync nil — atomic but not durable; the shutdown flush already
            ;; syncs, the periodic one now matches it.)
            (bitcoin-lisp.storage:coins-view-cache-flush view :sync t)))
        ;; Phase 3: commit by re-saving chainstate without the marker.
        (when chainstate
          (bitcoin-lisp.storage:save-state chainstate :in-transition nil))
        (log-info "~A flush: chainstate~@[~A~] at height ~D"
                  label
                  (let ((suffix (and chainstate
                                     (bitcoin-lisp.storage:chain-state-storage-suffix
                                      chainstate))))
                    (and suffix (plusp (length suffix)) suffix))
                  (and chainstate
                       (bitcoin-lisp.storage:current-height chainstate))))
    (error (c)
      ;; Was log-warn before — surfaced silently. Bumped to log-error so
      ;; persistence failures are obvious in the log instead of getting
      ;; lost between progress lines.
      (log-error "~A flush FAILED: ~A" label c))))

(defun do-flush (&optional (chainstate (and *node* (node-current-chainstate *node*))))
  "Flush CHAINSTATE (default: the node's current chainstate) and run the
per-cycle bookkeeping: reset the periodic-flush triggers, request a major GC
so reachable post-flush memory is the only thing in the old generations next
time we measure (the same pattern as Bitcoin Core's CCoinsViewCache::Flush
returning bytes freed to the system allocator), and log memory snapshots."
  (log-memory-snapshot "pre-flush")
  (%flush-chainstate chainstate)
  (setf *last-flush-universal-time* (get-universal-time)
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
         (view (and cs (bitcoin-lisp.storage:chain-state-coins-view cs))))
    (incf *blocks-since-flush*)
    (when (zerop *last-flush-universal-time*)
      (setf *last-flush-universal-time* (get-universal-time)))
    (when (or (>= *blocks-since-flush* +flush-every-n-blocks+)
              (>= (- (get-universal-time) *last-flush-universal-time*)
                  +flush-every-n-seconds+)
              ;; Size trigger (Bitcoin Core dbcache): flush once the coins cache
              ;; reaches its memory budget, so it can't grow unbounded between the
              ;; block-count / time flushes. The budget is per-chainstate while an
              ;; assumeutxo background sync splits it (maybe-rebalance-caches).
              (and view
                   (>= (bitcoin-lisp.storage:view-mem-bytes view)
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
      (setf *last-flush-universal-time* (get-universal-time)
            *blocks-since-flush* 0)
      #+sbcl (sb-ext:gc :full t)
      (log-memory-snapshot "post-flush"))))

(defvar *blockfilterindex-stall-logged* nil
  "One-shot latch so a stalled block filter index (non-contiguous connect
refused) logs a single warning instead of one per block until restart.")

(defun index-block-filter (chainstate block block-hash height spent-utxos)
  "Connect-time hook: add BLOCK's BIP158 basic filter to the running node's
block filter index, if one is enabled. CHAINSTATE is the chainstate the
block connected to; signals from any chainstate other than the node's
VALIDATED one are dropped — indexes index blocks in order from genesis, so
they bind Core's ValidatedChainstate (init.cpp:1367-1383) and must ignore
an unvalidated snapshot chainstate's tip-range connects. SPENT-UTXOS is the
undo list the UTXO apply produced. Never signals -- a filter-index failure
must not abort a block connect -- so consensus is unaffected whether the
index is on or off."
  (let ((bfi (and *node* (node-blockfilterindex *node*))))
    (when (and bfi (bitcoin-lisp.storage:blockfilterindex-enabled bfi)
               (eq chainstate (node-validated-chainstate *node*)))
      (handler-case
          (multiple-value-bind (filter status)
              (bitcoin-lisp.storage:blockfilterindex-add-block
               bfi block block-hash height spent-utxos)
            (when (and (eq status :noncontiguous)
                       (not *blockfilterindex-stall-logged*))
              (setf *blockfilterindex-stall-logged* t)
              (log-warn "Block filter index stalled at height ~D: gap below ~
best-indexed height ~D; the startup backfill will heal it on next restart"
                        height
                        (bitcoin-lisp.storage:blockfilterindex-height bfi)))
            filter)
        (error (e)
          (log-warn "Block filter index failed at height ~D: ~A" height e)
          nil)))))

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
         (tip-hash (bitcoin-lisp.storage:best-block-hash cs))
         (tip-entry (and tip-hash (bitcoin-lisp.storage:get-block-index-entry cs tip-hash)))
         (tip-height (bitcoin-lisp.storage:current-height cs)))
    (when (or (null tip-entry) (zerop tip-height))
      (log-info "Reindex-chainstate: empty chain, nothing to rebuild")
      (return-from do-reindex-chainstate))
    (log-info "Reindex-chainstate: rebuilding UTXO set from ~D stored blocks..." tip-height)
    ;; Active chain genesis+1 .. tip, ascending (push while walking prev-entry
    ;; down from the tip leaves the list in height order).
    (let ((entries '()))
      (loop with e = tip-entry
            while (and e (plusp (bitcoin-lisp.storage:block-index-entry-height e)))
            do (push e entries)
               (setf e (bitcoin-lisp.storage:block-index-entry-prev-entry e)))
      ;; Rewind the chainstate to genesis and persist it WITH the
      ;; in-transition marker BEFORE touching the coins DB: from here until
      ;; the first replay flush commits, a crash is detected at load-state
      ;; and resolved by recover-inconsistent-chainstate's genesis branch
      ;; (re-wipe + clear), never loaded as clean state over a gutted set.
      (bitcoin-lisp.storage:update-chain-tip
       cs (bitcoin-lisp.storage::chain-state-genesis-hash cs) 0)
      (bitcoin-lisp.storage:save-state cs :in-transition t)
      ;; Empty the coins view.
      (let ((erased (bitcoin-lisp.storage:coins-view-cache-wipe utxo)))
        (log-info "Reindex-chainstate: erased ~D coin~:P; replaying..." erased))
      ;; NB: the coinstatsindex is opened AFTER this runs; its rebuild is
      ;; forced in its own init block (keyed off the reindex flag), not here.
      ;; The blockfilterindex is left alone -- its filters are over block
      ;; scripts, unaffected by a UTXO-set rebuild.
      ;; Replay every block's UTXO effects.
      (let ((n 0) (last-report (get-internal-real-time)))
        (block replay
          (dolist (entry entries)
            (let* ((hash (bitcoin-lisp.storage:block-index-entry-hash entry))
                   (height (bitcoin-lisp.storage:block-index-entry-height entry))
                   (blk (bitcoin-lisp.storage:get-block store hash)))
              (unless blk
                (log-warn "Reindex-chainstate: block at height ~D missing from store; ~
stopping (UTXO set rebuilt to height ~D)" height (1- height))
                (return-from replay))
              ;; Apply removes spent prevouts + adds spendable outputs (the
              ;; unspendable skip lives in apply-block-to-utxo-set). Discard the
              ;; returned undo list -- the on-disk undo files are unchanged.
              (bitcoin-lisp.storage:apply-block-to-utxo-set utxo blk height)
              (bitcoin-lisp.storage:update-chain-tip cs hash height)
              (incf n)
              ;; Size-triggered flushes go through the 3-phase commit like
              ;; the periodic flush: marker at the replay height, one atomic
              ;; synced coins batch, marker cleared — so the on-disk pair is
              ;; always chainstate.dat <= coins DB by an identifiable gap.
              (when (>= (bitcoin-lisp.storage:view-mem-bytes utxo)
                        (large-coins-cache-threshold *coins-cache-budget-bytes*))
                (%flush-chainstate cs :label "Reindex"))
              (let ((now (get-internal-real-time)))
                (when (> (- now last-report) internal-time-units-per-second)
                  (log-info "Reindex-chainstate: height ~D (~,1F%)"
                            height (* 100.0 (/ height tip-height)))
                  (setf last-report now))))))
        (%flush-chainstate cs :label "Reindex")
        (log-info "Reindex-chainstate complete: ~D block~:P re-applied, tip at height ~D"
                  n (bitcoin-lisp.storage:current-height cs))))))

(defun force-compact-databases ()
  "Full-compact every LevelDB the node has open -- the coins/chainstate DB plus
the block-filter and coinstats indexes -- reclaiming the disk that tombstones
still pin after a large deletion churn (e.g. a reindex-chainstate wipe). Mirrors
Bitcoin Core's -forcecompactdb, which sets CDBWrapper force_compact on each
database it opens. Synchronous and potentially slow on a large chainstate."
  (flet ((compact (label db)
           (when db
             (log-info "Starting database compaction of ~A" label)
             (bitcoin-lisp.storage:leveldb-compact db)
             (log-info "Finished database compaction of ~A" label))))
    (let ((utxo (node-utxo-set *node*))
          (bfi (node-blockfilterindex *node*))
          (csi (node-coinstatsindex *node*)))
      (when utxo
        (log-info "Starting database compaction of chainstate")
        (bitcoin-lisp.storage:coins-view-cache-compact utxo)
        (log-info "Finished database compaction of chainstate"))
      (when bfi (compact "blockfilterindex" (bitcoin-lisp.storage:blockfilterindex-db bfi)))
      (when csi (compact "coinstatsindex" (bitcoin-lisp.storage:coinstatsindex-db csi))))))

(defun index-block-coinstats (chainstate block block-hash height spent-utxos)
  "Connect-time hook: fold BLOCK into the running node's coinstatsindex, if
one is enabled. CHAINSTATE is the chainstate the block connected to; like
index-block-filter, only the node's VALIDATED chainstate's connects are
indexed — the running MuHash must be contiguous from genesis, which an
unvalidated snapshot chainstate's tip-range blocks are not. SPENT-UTXOS is
the undo list the UTXO apply produced; the block subsidy is derived from
HEIGHT. Never signals -- an index failure must not abort a block connect --
so consensus is unaffected whether the index is on or off. Returns NIL (and
stalls quietly) if the parent height's record is missing (non-contiguous);
the startup backfill heals such gaps on restart."
  (let ((csi (and *node* (node-coinstatsindex *node*))))
    (when (and csi (bitcoin-lisp.storage:coinstatsindex-enabled csi)
               (eq chainstate (node-validated-chainstate *node*)))
      (handler-case
          (bitcoin-lisp.storage:coinstatsindex-add-block
           csi block block-hash height spent-utxos
           (bitcoin-lisp.validation:calculate-block-subsidy height))
        (error (e)
          (log-warn "Coinstats index failed at height ~D: ~A" height e)
          nil)))))

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
         (bitcoin-lisp.rpc:wallet-manager-has-wallets-p manager)
         manager)))

(defun wallet-notify-block-connected (chainstate block block-hash height)
  "Connect-time hook: let loaded wallets scan BLOCK (Core
CWallet::blockConnected). Only the active chainstate's connects are
delivered — an assumeutxo historical (targeted) chainstate's re-derived
old blocks are Core's ChainstateRole::historical, which the wallet ignores
(wallet.cpp:1526-1529)."
  (let ((manager (%wallet-hook-manager)))
    (when (and manager
               (not (bitcoin-lisp.storage:chain-state-target-blockhash chainstate)))
      (handler-case
          (bitcoin-lisp.rpc:wallets-block-connected
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
               (not (bitcoin-lisp.storage:chain-state-target-blockhash chainstate)))
      (handler-case
          (bitcoin-lisp.rpc:wallets-block-disconnected manager block height)
        (error (e)
          (log-error "Wallet processing of disconnected block at height ~D FAILED: ~A"
                     height e))))))

(defun wallet-notify-mempool-tx-added (tx)
  "Mempool hook: Core CWallet::transactionAddedToMempool."
  (let ((manager (%wallet-hook-manager)))
    (when manager
      (handler-case
          (bitcoin-lisp.rpc:wallets-mempool-tx-added
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
            (bitcoin-lisp.rpc:wallets-mempool-tx-removed
             manager (node-mempool *node*) tx reason)
          (error (e)
            (log-error "Wallet processing of mempool tx removal FAILED: ~A" e)))))))

(defun install-shutdown-handler ()
  "Trap SIGTERM and SIGINT so kill <pid> / Ctrl-C calls stop-node and persists
   chain state and UTXO set before exit. Without this, SIGKILL is the only way
   to stop a long-running node and IBD must restart from genesis on next boot.

   Also installs a fail-fast debugger hook: any unhandled error (including
   heap-exhausted) logs a stack and exits non-zero rather than dropping into
   LDB on a tty no one is reading."
  #+sbcl
  (let ((handler
          (lambda (&rest _)
            (declare (ignore _))
            (format *error-output* "~&[shutdown] caught signal — saving state~%")
            ;; Under the supervisor (a main-thread watchdog is polling), only
            ;; REQUEST the stop. The kernel delivers the signal to whichever
            ;; thread it likes, and running the teardown here would race the
            ;; watchdog's exit exactly like the other internal stop paths did —
            ;; SIGTERM only survived that race by delivery luck. The watchdog
            ;; runs stop-node and exits 0 itself.
            (if *shutdown-watchdog-running*
                (request-node-shutdown "SIGTERM/SIGINT" :exit-code +node-exit-clean+)
                ;; No watchdog (REPL / embedded): nobody else would stop the
                ;; node, so do it here and exit as before.
                (progn
                  (ignore-errors (stop-node))
                  ;; Per-block script-check worker threads (bt:make-thread :name
                  ;; "script-check-N" in validate-block.lisp) are non-daemon and
                  ;; can outlive stop-node if validation was in progress when the
                  ;; sync thread was destroyed. Without a timeout, sb-ext:exit
                  ;; blocks forever waiting for them (incident 2026-05-11: node
                  ;; logged "Node stopped" but SBCL process hung 6+ minutes,
                  ;; eventually needed SIGKILL). Give 5 seconds for any in-flight
                  ;; worker to finish naturally, then force-exit. Bitcoin Core's
                  ;; CCheckQueue (checkqueue.h:206-225) has an explicit stop flag
                  ;; + condvar to join workers; we use a coarser timeout because
                  ;; our workers are ephemeral per-block, not a persistent pool.
                  (sb-ext:exit :code 0 :timeout 5))))))
    (sb-sys:enable-interrupt sb-unix:sigterm handler)
    (sb-sys:enable-interrupt sb-unix:sigint handler))
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
              (let ((suffix (bitcoin-lisp.storage:chain-state-storage-suffix cs)))
                (and (plusp (length suffix)) suffix)))
    (%flush-chainstate cs :label "Shutdown")
    (bitcoin-lisp.storage:close-chainstate-coins-view cs)))

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

  ;; Persist reconnection anchors while peers are still connected (before the
  ;; teardown below disconnects them).
  (save-anchors *node*)

  ;; Stop RPC server first
  (bitcoin-lisp.rpc:stop-rpc-server)

  ;; Signal the node to stop. request-ibd-stop reaches the IBD inner
  ;; loops, which can otherwise run for hours after node-running flips
  ;; (the outer sync loop only checks between run-ibd passes).
  (setf (node-running *node*) nil)
  (bitcoin-lisp.networking:request-ibd-stop)

  ;; Stop the torcontrol client: closing the control connection is what tears
  ;; the ephemeral onion service down inside Tor (no DEL_ONION, like Core).
  (when (node-tor-controller *node*)
    (bitcoin-lisp.networking:stop-tor-control (node-tor-controller *node*))
    (setf (node-tor-controller *node*) nil))

  ;; Stop the inbound listeners: close the sockets (unblocks accept) and let
  ;; the accept threads observe node-running=nil and exit (accept timeout 1s).
  (when (node-listener-socket *node*)
    (bitcoin-lisp.networking:close-listener (node-listener-socket *node*))
    (setf (node-listener-socket *node*) nil))
  (when (node-onion-listener-socket *node*)
    (bitcoin-lisp.networking:close-listener (node-onion-listener-socket *node*))
    (setf (node-onion-listener-socket *node*) nil))
  ;; One shared deadline bounds the TOTAL wait for both accept threads.
  (let ((deadline (+ (get-internal-real-time) (* 5 internal-time-units-per-second))))
    (bitcoin-lisp.networking:join-thread-or-destroy
     (node-listener-thread *node*) :deadline deadline)
    (bitcoin-lisp.networking:join-thread-or-destroy
     (node-onion-listener-thread *node*) :deadline deadline))
  (setf (node-listener-thread *node*) nil
        (node-onion-listener-thread *node*) nil)
  ;; Disconnect any inbound peers not yet merged into the peer list. The listener
  ;; thread is already joined above, but take the lock for consistency.
  (let ((pending (bt:with-recursive-lock-held ((node-lock *node*))
                   (prog1 (node-pending-inbound-peers *node*)
                     (setf (node-pending-inbound-peers *node*) nil)))))
    (dolist (peer pending)
      (handler-case (bitcoin-lisp.networking:disconnect-peer peer) (error () nil))))

  ;; Wait for sync thread to finish (with timeout)
  (when (and (node-sync-thread *node*)
             (bt:thread-alive-p (node-sync-thread *node*)))
    (log-info "Waiting for sync thread to stop...")
    (let ((deadline (+ (get-internal-real-time)
                       ;; 10 minutes — long enough that a single heavy block's
                       ;; validation finishes and connect-block updates UTXO set
                       ;; + chain tip atomically, so destroy-thread fallback
                       ;; (which can corrupt mid-update state) is virtually
                       ;; never needed.
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
        (bitcoin-lisp.networking:disconnect-peer peer)
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
    (bitcoin-lisp.mempool:save-fee-stats (node-fee-estimator *node*)))

  ;; Save mempool (Core DumpMempool)
  (let ((path (bitcoin-lisp.mempool:mempool-dat-path (node-data-directory *node*))))
    (when (and path (node-mempool *node*))
      (log-info "Saving mempool (~D entries)..."
                (bitcoin-lisp.mempool:save-mempool-file (node-mempool *node*) path))))

  ;; Save peer address book
  (when (node-address-book *node*)
    (log-info "Saving peer address book...")
    (bitcoin-lisp.networking:save-address-book
     (node-address-book *node*)
     (bitcoin-lisp.networking:peers-dat-path (node-data-directory *node*))))

  ;; Final banlist dump (Core ~BanMan calls DumpBanlist, banman.cpp:26),
  ;; then detach the path so post-shutdown mutations stop writing.
  (bitcoin-lisp.networking:save-banlist)
  (setf bitcoin-lisp.networking:*banlist-path* nil)

  ;; Unload wallets (writes each wallet's best-block marker, closes its DB)
  (when (node-wallet-manager *node*)
    (log-info "Unloading wallets...")
    (bitcoin-lisp.rpc:close-wallet-manager (node-wallet-manager *node*))
    (setf (node-wallet-manager *node*) nil))

  ;; Close transaction index
  (when (node-tx-index *node*)
    (log-info "Closing transaction index...")
    (bitcoin-lisp.storage:close-tx-index (node-tx-index *node*)))

  ;; Close block filter index
  (when (node-blockfilterindex *node*)
    (log-info "Closing block filter index...")
    (bitcoin-lisp.storage:close-blockfilterindex (node-blockfilterindex *node*)))

  ;; Close coinstats index
  (when (node-coinstatsindex *node*)
    (log-info "Closing coinstats index...")
    (bitcoin-lisp.storage:close-coinstatsindex (node-coinstatsindex *node*)))

  ;; Cleanup secp256k1
  (bitcoin-lisp.crypto:cleanup-secp256k1)

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
  (bitcoin-lisp.storage:save-file-with-crc32
   path
   (lambda (stream)
     (loop for shift in '(24 16 8 0)
           do (write-byte (ldb (byte 8 shift) +anchors-magic-v2+) stream))
     (write-byte (length entries) stream)
     (dolist (e entries)
       (destructuring-bind (net bytes port) e
         (write-byte (bitcoin-lisp.networking:network-key-id net) stream)
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
             (let ((net (bitcoin-lisp.networking:key-id-network (aref bytes pos)))
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
                     (bitcoin-lisp.networking:parse-network-address
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
            (lambda (p) (and (not (bitcoin-lisp.networking:peer-inbound p))
                             (eq (bitcoin-lisp.networking:peer-state p) :ready)))
            (node-peers node)))
         ;; Prefer block-relay-only peers as anchors (Core anchors are
         ;; block-relay: an attacker who fed us a poisoned addrman can't
         ;; substitute a peer we were just block-relay-connected to). Fall back
         ;; to full-relay outbound if we have no block-relay peers.
         (block-relay (remove-if-not
                       (lambda (p) (eq (bitcoin-lisp.networking:peer-conn-type p)
                                       :block-relay))
                       ready-outbound))
         (ready (or block-relay ready-outbound))
         (default-port (network-port (node-network node)))
         (entries
           (loop for p in (subseq ready 0 (min +max-anchors+ (length ready)))
                 for (net bytes) = (multiple-value-list
                                    (bitcoin-lisp.networking:parse-network-address
                                     (bitcoin-lisp.networking:peer-address p)))
                 when net                        ; hostname peers (addnode) skipped
                   collect (list net bytes
                                 (let ((conn (bitcoin-lisp.networking::peer-connection p)))
                                   (if conn
                                       (bitcoin-lisp.networking::connection-port conn)
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
Missing/corrupt file is ignored; a v1-era file migrates (see
parse-anchor-entries) and the next save rewrites it as v2. Only networks that
are dialable under the current config (dialable-network-p: onion needs a Tor
proxy, cjdns needs -cjdnsreachable) and reachable (-onlynet) become dial
candidates."
  (let ((bytes (bitcoin-lisp.storage:load-file-with-crc32
                (anchors-dat-path (node-data-directory node)) 6)))
    (when bytes
      (setf *pending-anchor-addresses*
            (loop for (net addr-bytes port) in (parse-anchor-entries bytes)
                  when (and (bitcoin-lisp.networking:dialable-network-p net)
                            (bitcoin-lisp.networking:reachable-network-p net))
                    collect (cons (bitcoin-lisp.networking:network-address-to-string
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
          (and bitcoin-lisp.networking:*proxy*
               (or (bitcoin-lisp.networking:reachable-network-p :ipv4)
                   (bitcoin-lisp.networking:reachable-network-p :ipv6))
               t)))
    (remove-if-not (lambda (addr)
                     (let ((net (bitcoin-lisp.networking:parse-network-address addr)))
                       (if net
                           (bitcoin-lisp.networking:reachable-network-p net)
                           name-proxy-p)))
                   addresses)))

(defun %record-outbound-result (address-book addr port peer success)
  "Record an outbound dial outcome for ADDR:PORT in ADDRESS-BOOK, adding the
entry if new (network-typed, so IPv6/onion/cjdns peers get addrman credit
too): SUCCESS => Good + Connected, failure => Attempt with count-failure
(Core CConnman's addrman feedback in ConnectNode/OpenNetworkConnection).
Hostname dial targets (unparseable as addresses) are skipped."
  (when address-book
    (multiple-value-bind (net ip-bytes)
        (bitcoin-lisp.networking:parse-network-address addr)
      (when net
        (unless (bitcoin-lisp.networking:address-book-lookup
                 address-book ip-bytes port net)
          (bitcoin-lisp.networking:address-book-add
           address-book
           (bitcoin-lisp.networking:make-peer-address
            :net net :ip ip-bytes :port port
            :services (if (and success peer)
                          (bitcoin-lisp.networking:peer-services peer)
                          0)
            :last-seen (bitcoin-lisp.serialization:get-unix-time))))
        (if success
            (progn
              (bitcoin-lisp.networking:address-book-good
               address-book ip-bytes port
               (bitcoin-lisp.serialization:get-unix-time) net)
              (bitcoin-lisp.networking:address-book-connected
               address-book ip-bytes port
               (bitcoin-lisp.serialization:get-unix-time) net))
            (bitcoin-lisp.networking:address-book-attempt
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
  (let ((address-book (node-address-book node))
        (addresses '()))
    ;; Warm start: select peers from the addrman (new/tried buckets,
    ;; eclipse-resistant) rather than a single global score ranking.
    (when (and address-book
               (>= (bitcoin-lisp.networking:address-book-count address-book) 8))
      (bitcoin-lisp.networking:resolve-tried-collisions address-book)
      (log-info "Using peer address book (~D entries)..."
                (bitcoin-lisp.networking:address-book-count address-book))
      (let ((seen (make-hash-table :test 'equal))
            (picks '()))
        (dotimes (i (* max-peers 8))
          ;; select-dialable-address, never raw select: post-BIP155 the book
          ;; can hold records not dialable under the current config (torv3
          ;; without a Tor proxy, i2p always, cjdns without -cjdnsreachable).
          (let ((pa (bitcoin-lisp.networking:select-dialable-address address-book)))
            (when pa
              (let ((str (bitcoin-lisp.networking:peer-address-string pa))
                    (port (bitcoin-lisp.networking:peer-address-port pa)))
                (unless (gethash str seen)
                  (setf (gethash str seen) t)
                  (push (cons str (and (plusp port) port)) picks))))))
        (setf addresses (nreverse picks))))
    ;; Fall back to DNS seeds if not enough candidates (-dnsseed=0 forbids
    ;; the query entirely, Core DEFAULT_DNSSEED/ThreadDNSAddressSeed).
    (when (and (< (length addresses) 8)
               (not *dns-seed-enabled*))
      (log-info "DNS seeding disabled (-dnsseed=0)"))
    (when (and (< (length addresses) 8) *dns-seed-enabled*)
      (log-info "Discovering peers from DNS seeds...")
      (let* ((dns-addrs (bitcoin-lisp.networking:discover-peers))
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
    (when (and (eq (node-network node) :testnet4)
               ;; -fixedseeds=0 forbids the hardcoded fallback (Core
               ;; net.cpp:2571-2572 "Fixed seeds are disabled").
               *fixed-seeds-enabled*
               (let ((groups (remove-duplicates
                              (remove nil (mapcar (lambda (c)
                                                    (bitcoin-lisp.networking:ip-netgroup
                                                     (car c)))
                                                  addresses))
                              :test #'string=)))
                 (< (length groups) 8)))
      (log-info "Merging testnet4 fixed-seed list (~D peers, ~D /16 groups)"
                (length bitcoin-lisp.networking:*testnet4-fixed-seeds*)
                (length (remove-duplicates
                         (mapcar #'bitcoin-lisp.networking:ip-netgroup
                                 bitcoin-lisp.networking:*testnet4-fixed-seeds*)
                         :test #'string=)))
      (setf addresses
            (remove-duplicates
             (append addresses
                     (mapcar (lambda (a) (cons a nil))
                             (%reachable-seed-addresses
                              bitcoin-lisp.networking:*testnet4-fixed-seeds*)))
             :key #'car :test #'string=)))

    ;; Diversify by /16 netgroup so the first 8 connection attempts spread
    ;; across distinct operators (incident 2026-05-11: 8-of-8 peers were
    ;; from 103.165.192.x wiz.biz nodes — one stall stalled the whole
    ;; sync). Mirrors Bitcoin Core's addrman netgroup bucket selection
    ;; (netaddress.cpp CNetAddr::GetGroup).
    (setf addresses (bitcoin-lisp.networking:diversify-by-netgroup addresses
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
              (let ((peer (bitcoin-lisp.networking:connect-peer addr dial-port)))
                (when peer
                  (setf (bitcoin-lisp.networking:peer-address peer) addr)
                  (log-info "Connected to ~A" addr)
                  ;; Perform handshake
                  (when (bitcoin-lisp.networking:perform-handshake peer)
                    (log-info "Handshake complete with ~A (~A, height ~D)"
                              addr
                              (bitcoin-lisp.networking:peer-user-agent peer)
                              (bitcoin-lisp.networking:peer-start-height peer))
                    ;; Send feature negotiation messages
                    (bitcoin-lisp.networking:send-post-handshake-messages peer)
                    ;; Record success in address book (add if not present)
                    (%record-outbound-result address-book addr dial-port peer t)
                    ;; Send compact block negotiation (BIP 152)
                    (bitcoin-lisp.networking:send-compact-block-negotiation peer)
                    (bt:with-recursive-lock-held ((node-lock node))
                      (push peer (node-peers node)))
                    (incf connected))
                  (unless (eq (bitcoin-lisp.networking:peer-state peer) :ready)
                    (bitcoin-lisp.networking:disconnect-peer peer))))
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
            (bitcoin-lisp.networking:check-compact-block-timeout peer)
            ;; Check ping/pong health
            (let ((status (bitcoin-lisp.networking:check-peer-health peer)))
              (when (eq status :disconnect)
                (push peer to-disconnect))))
        (error () (push peer to-disconnect))))
    (dolist (peer to-disconnect)
      (log-warn "Disconnecting unresponsive peer ~A"
                (bitcoin-lisp.networking:peer-address peer))
      (handler-case
          (bitcoin-lisp.networking:disconnect-peer peer)
        (error (c) (declare (ignore c))))
      (bt:with-recursive-lock-held ((node-lock node))
        (setf (node-peers node) (remove peer (node-peers node)))))
    (length to-disconnect)))

(defun outbound-full-relay-peer-p (peer)
  "T iff PEER is a ready outbound full-relay connection — the only kind that
counts toward the outbound full-relay target (Core CNode::IsFullOutboundConn:
m_conn_type == OUTBOUND_FULL_RELAY, which is never inbound). Inbound peers
and block-relay/feeler outbound peers are deliberately excluded."
  (and (eq (bitcoin-lisp.networking:peer-state peer) :ready)
       (not (bitcoin-lisp.networking:peer-inbound peer))
       (eq (bitcoin-lisp.networking:peer-conn-type peer) :outbound-full-relay)))

(defun count-outbound-full-relay-peers (peers)
  "Count ready outbound full-relay peers among PEERS (Core nOutboundFullRelay).
Inbound connections are excluded so an attacker filling our inbound slots
cannot suppress replacement outbound dials (eclipse-attack prevention)."
  (count-if #'outbound-full-relay-peer-p peers))

(defun replace-disconnected-peers (node)
  "Replace disconnected peers to maintain target peer count.
Returns the number of new peers connected."
  ;; Reap disconnected peers first — this also cleans up peers that
  ;; setnetworkactive dropped, even while networking stays disabled.
  (bt:with-recursive-lock-held ((node-lock node))
    (setf (node-peers node)
          (remove-if (lambda (p)
                       (eq (bitcoin-lisp.networking:peer-state p) :disconnected))
                     (node-peers node))))
  ;; setnetworkactive off: don't dial replacements.
  (unless (node-network-active node)
    (return-from replace-disconnected-peers 0))
  ;; Count ONLY outbound full-relay peers toward the outbound target — never
  ;; inbound, never block-relay/feeler. Core's ThreadOpenConnections counts
  ;; nOutboundFullRelay via IsFullOutboundConn() (net.cpp:2648-2657,2718) and
  ;; explicitly keeps inbound out of the arithmetic: inbound connections are
  ;; free for an attacker to make, so letting them satisfy the outbound
  ;; target is an eclipse primitive — 8 attacker inbounds previously
  ;; suppressed dialing any honest outbound replacement here. The inbound
  ;; population has its own separate cap (+max-inbound-peers+, enforced at
  ;; merge time in merge-inbound-peers). Block-relay-only peers are a
  ;; separate additive pool maintained by maintain-block-relay-peers (Core
  ;; keeps m_max_outbound_block_relay distinct from
  ;; m_max_outbound_full_relay); folding them in here would let 2 idle
  ;; block-relay slots starve replacement of a dropped full-relay peer.
  ;; (Known simplification vs Core: addnode peers are typed
  ;; :outbound-full-relay in our code, so they do count here, whereas Core's
  ;; MANUAL connections are additive.)
  (let* ((active-count (count-outbound-full-relay-peers (node-peers node)))
         (needed (- (node-max-peers node) active-count)))
    (when (<= needed 0)
      (return-from replace-disconnected-peers 0))

    ;; Get addresses already in use
    (let ((used-addrs (mapcar #'bitcoin-lisp.networking:peer-address
                              (node-peers node)))
          (connected 0))
      (dolist (candidate (node-known-addresses node))
        ;; Stop attempting new connect+handshake cycles the moment shutdown is
        ;; requested — each one can otherwise block (connect timeout + handshake
        ;; read) and delay the sync thread reaching its node-running checkpoint.
        (when (or (>= connected needed)
                  (bitcoin-lisp.networking:ibd-stop-requested-p))
          (return))
        (let ((addr (car candidate)))
          (unless (member addr used-addrs :test #'string=)
            (handler-case
                (let ((peer (bitcoin-lisp.networking:connect-peer
                             addr (or (cdr candidate)
                                      (network-port (node-network node))))))
                  (when peer
                    (setf (bitcoin-lisp.networking:peer-address peer) addr)
                    (when (bitcoin-lisp.networking:perform-handshake peer)
                      (log-info "Replacement peer connected: ~A" addr)
                      ;; Send feature negotiation messages
                      (bitcoin-lisp.networking:send-post-handshake-messages peer)
                      ;; Send compact block negotiation (BIP 152)
                      (bitcoin-lisp.networking:send-compact-block-negotiation peer)
                      (bt:with-recursive-lock-held ((node-lock node))
                        (push peer (node-peers node)))
                      (incf connected))
                    (unless (eq (bitcoin-lisp.networking:peer-state peer) :ready)
                      (bitcoin-lisp.networking:disconnect-peer peer))))
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

(defun peer-connected-to-host-p (node host)
  "T if a peer with address HOST is currently in the node's peer list."
  (bt:with-recursive-lock-held ((node-lock node))
    (and (find host (node-peers node)
               :key #'bitcoin-lisp.networking:peer-address :test #'string=)
         t)))

(defun establish-outbound-peer (node host port &key (conn-type :outbound-full-relay))
  "Full outbound connect + handshake to HOST:PORT, pushing the ready peer onto
node-peers. CONN-TYPE (:outbound-full-relay or :block-relay) sets the peer's
connection type. Returns the peer or NIL. MUST run on the sync thread so
node-peers stays single-writer. No-op when networking is disabled."
  (when (node-network-active node)
    (handler-case
        (let ((peer (bitcoin-lisp.networking:connect-peer host port)))
          (when peer
            (setf (bitcoin-lisp.networking:peer-address peer) host)
            (if (bitcoin-lisp.networking:perform-handshake peer :conn-type conn-type)
                (progn
                  (bitcoin-lisp.networking:send-post-handshake-messages peer)
                  (bitcoin-lisp.networking:send-compact-block-negotiation peer)
                  (bt:with-recursive-lock-held ((node-lock node))
                    (push peer (node-peers node)))
                  (log-info "Added-node peer connected: ~A" host)
                  peer)
                (progn (bitcoin-lisp.networking:disconnect-peer peer) nil))))
      (error (c)
        (log-debug "Added-node connect to ~A:~D failed: ~A" host port c)
        nil))))

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
          (unless (peer-connected-to-host-p node host)
            (establish-outbound-peer node host port)))))
    ;; Maintain persistent added-node connections.
    (dolist (spec (node-added-nodes node))
      (multiple-value-bind (host port) (parse-node-endpoint node spec)
        (unless (peer-connected-to-host-p node host)
          (establish-outbound-peer node host port))))))

(defconstant +target-block-relay-peers+ 2
  "Dedicated block-relay-only outbound slots (Bitcoin Core opens 2). They carry
blocks/headers but no tx relay -- anti-partition insurance and the source of
reconnection anchors.")

(defconstant +feeler-interval-seconds+ 120
  "Minimum spacing between feeler probes (Core FEELER_INTERVAL averages ~2 min).")

(defvar *last-feeler-time* 0
  "get-universal-time of the last feeler attempt, for rate-limiting.")

(defun peers-of-conn-type (node type)
  "Count current peers whose connection type is TYPE."
  (bt:with-recursive-lock-held ((node-lock node))
    (count type (node-peers node)
           :key #'bitcoin-lisp.networking:peer-conn-type)))

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
        (let ((pa (bitcoin-lisp.networking:select-dialable-address ab :new-only new-only)))
          (when pa
            (let ((host (bitcoin-lisp.networking:peer-address-string pa))
                  (port (bitcoin-lisp.networking:peer-address-port pa)))
              (unless (peer-connected-to-host-p node host)
                (return-from %addrman-pick-unconnected
                  (values host (and (plusp port) port)))))))))))

(defun maintain-block-relay-peers (node)
  "Ensure up to +target-block-relay-peers+ block-relay-only outbound peers.
Each carries blocks/headers only (relay=0), never tx relay."
  (when (and (node-network-active node) (node-address-book node))
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
      (let ((peer (bitcoin-lisp.networking:connect-peer host port)))
        (when peer
          (setf (bitcoin-lisp.networking:peer-address peer) host)
          (when (bitcoin-lisp.networking:perform-handshake peer :conn-type :feeler)
            (multiple-value-bind (net ip-bytes)
                (bitcoin-lisp.networking:parse-network-address host)
              (when net
                (bitcoin-lisp.networking:address-book-good
                 (node-address-book node) ip-bytes port
                 (bitcoin-lisp.serialization:get-unix-time) net)))
            (log-debug "Feeler validated ~A (new -> tried)" host))
          (bitcoin-lisp.networking:disconnect-peer peer)))
    (error (c)
      (log-debug "Feeler to ~A:~D failed: ~A" host port c))))

(defun maybe-do-feeler (node)
  "Rate-limited: probe one addrman 'new' address with a feeler to validate it
into 'tried'."
  (let ((now (get-universal-time)))
    (when (and (node-network-active node) (node-address-book node)
               (>= (- now *last-feeler-time*) +feeler-interval-seconds+))
      (setf *last-feeler-time* now)
      (multiple-value-bind (ip port) (%addrman-pick-unconnected node :new-only t)
        (when ip
          (do-feeler-connection node ip (or port (network-port (node-network node)))))))))

(defun maintain-peers (node)
  "Run periodic peer maintenance: health checks, reconnection, dedicated
block-relay-only slots, and an occasional feeler probe."
  (check-peers-health node)
  (connect-added-nodes node)
  (replace-disconnected-peers node)
  (maintain-block-relay-peers node)
  (maybe-do-feeler node))

;;;; Blockchain Synchronization

(defun sync-blockchain (node)
  "Run one IBD/follow-tip cycle against connected peers.

Doesn't short-circuit on `peer-start-height` since that value is frozen
at handshake and goes stale once the chain advances — start-ibd's
header-sync phase is what discovers new tips, and its block-download
phase exits quickly when there's nothing new to fetch."
  (unless (node-peers node)
    (log-warn "No peers connected, cannot sync")
    (return-from sync-blockchain 0))

  ;; IBD drives the current chainstate (its tip and coins view). When an
  ;; assumeutxo background sync is active, the historical chainstate rides
  ;; along as a second download cursor inside the same IBD pass: run-ibd
  ;; queues its [historical-tip .. snapshot-base] range and routes received
  ;; blocks to whichever chainstate owns their height.
  (let ((chainstate (node-current-chainstate node))
        (peer-height (bitcoin-lisp.networking:peer-start-height (find-best-peer node))))
    (log-debug "Sync cycle: local height ~D, peer-start height ~D"
               (bitcoin-lisp.storage:current-height chainstate)
               peer-height)
    (bitcoin-lisp.networking::start-ibd
     (node-peers node)
     chainstate
     (bitcoin-lisp.storage:chain-state-coins-view chainstate)
     (node-block-store node)
     peer-height
     :historical-chainstate (node-historical-chainstate node)
     :fee-estimator (node-fee-estimator node)
     :recent-rejects (node-recent-rejects node)
     :mempool (node-mempool node)
     :address-book (node-address-book node))))


(defun find-best-peer (node)
  "Find the best peer for syncing (highest block height)."
  (let ((ready-peers (remove-if-not
                      (lambda (p)
                        (eq (bitcoin-lisp.networking:peer-state p) :ready))
                      (node-peers node))))
    (when ready-peers
      (first (sort (copy-list ready-peers) #'>
                   :key #'bitcoin-lisp.networking:peer-start-height)))))

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
            (bitcoin-lisp.storage:current-height (node-chain-state *node*)))
    (format t "  Best block: ~A~%"
            (bitcoin-lisp.crypto:bytes-to-hex
             (bitcoin-lisp.storage:best-block-hash (node-chain-state *node*)))))
  (format t "~%UTXO Set:~%")
  (when (node-utxo-set *node*)
    (format t "  UTXOs: ~D~%"
            (bitcoin-lisp.storage:utxo-count (node-utxo-set *node*))))
  (format t "~%Mempool:~%")
  (when (node-mempool *node*)
    (format t "  Transactions: ~D~%"
            (bitcoin-lisp.mempool:mempool-count (node-mempool *node*)))
    (format t "  Size: ~:D vbytes (~:D bytes memory)~%"
            (bitcoin-lisp.mempool:mempool-total-size (node-mempool *node*))
            (bitcoin-lisp.mempool:mempool-dynamic-usage (node-mempool *node*))))
  (format t "~%Peers:~%")
  (if (node-peers *node*)
      (dolist (peer (node-peers *node*))
        (format t "  - ~A (height ~D, latency ~Dms)~%"
                (bitcoin-lisp.networking:peer-user-agent peer)
                (bitcoin-lisp.networking:peer-start-height peer)
                (bitcoin-lisp.networking:peer-ping-latency peer)))
      (format t "  (no peers connected)~%"))
  (format t "~%")
  t)


