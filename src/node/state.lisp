(in-package #:bitcoin-lisp)

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
  ;; Wallet manager (bl.wallet:wallet-manager) fanning RPCs out to
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
      (internal-error "Cannot set the node's utxo-set: no current chainstate exists"))
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
         (synced (not bl.net:*cached-is-ibd*)))
    (values (health-ok-p alive seconds) seconds synced)))
