(in-package #:bitcoin-lisp)

;;;; Inbound listening: the accept loop and the onion listener.

(defvar *inbound-handshakes-in-flight* 0
  "Number of accepted inbound connections whose version handshake is still
running on its own thread. Counted with the hand-off queue by
INBOUND-CONNECTION-ALLOWED-P, so a connect flood cannot open more handshake
threads than the node would admit peers.")

(defvar *inbound-handshake-lock* (bt:make-lock "inbound-handshakes")
  "Guards *INBOUND-HANDSHAKES-IN-FLIGHT*.")

(defconstant +inbound-handshake-timeout-cap-seconds+ 15
  "Ceiling on how long ONE accepted connection's handshake thread may wait for
the peer, whatever -peertimeout says. Core needs no such cap -- its handshake
is driven by the shared socket handler, so a silent peer costs no thread -- but
ours is a thread per handshake and the functional framework writes
peertimeout=999999999 into every node's config.")

(defun inbound-handshakes-in-flight ()
  "How many accepted connections are mid-handshake right now."
  (bt:with-lock-held (*inbound-handshake-lock*) *inbound-handshakes-in-flight*))

(defun %run-inbound-handshake (node peer onion)
  "Run PEER's inbound version handshake and, if it succeeds, hand the peer to
the sync thread through PENDING-INBOUND-PEERS. Runs on its OWN thread.

Core adds an accepted socket to m_nodes at once (net.cpp:1854-1858) and lets
ThreadMessageHandler run the version exchange, so its accept loop never waits
on a peer. Ours ran PERFORM-INBOUND-HANDSHAKE inline on the listener thread,
which serialised every inbound connection behind the slowest handshake:
p2p_leak.py's first peer sends nothing at all, and the node's log shows the
second connection accepted 15 s after it and the third 30 s after it -- by
which time the first had been dropped, which is what p2p_leak.py:131 asserts
against. Bulk-connecting tests (p2p_eviction, p2p_getaddr_caching,
p2p_ibd_stalling) pay the same toll per peer.

The handshake's read budget is -peertimeout, Core's own bound on an unfinished
handshake (CConnman::InactivityCheck's `if (!node.fSuccessfullyConnected)'
arm behind ShouldRunInactivityChecks, net.cpp:2003-2006 and :2053-2058),
capped so one silent peer cannot pin a thread for the framework's
peertimeout=999999999."
  (unwind-protect
       (handler-case
           (if (bl.net:perform-inbound-handshake
                peer
                :timeout (min +inbound-handshake-timeout-cap-seconds+
                              bl:*handshake-timeout-seconds*))
               (progn
                 (bl.net:send-post-handshake-messages peer)
                 (bl.net:send-compact-block-negotiation peer)
                 ;; Published only now: the sync thread pumps a peer the moment
                 ;; it appears here, and these sends belong to the handshake.
                 (bt:with-recursive-lock-held ((node-lock node))
                   (push peer (node-pending-inbound-peers node)))
                 (log-cat "net"
                          "New inbound~:[~; onion~] peer connected: ~A, ~A"
                          onion
                          (bl.net:peer-user-agent peer)
                          (bl.net:peer-log-name peer))
                 t)
               (progn (bl.net:disconnect-peer peer) nil))
         (error (c)
           (log-debug "Inbound handshake error: ~A" c)
           (ignore-errors (bl.net:disconnect-peer peer))
           nil))
    (bt:with-lock-held (*inbound-handshake-lock*)
      (decf *inbound-handshakes-in-flight*))))

(defun admit-inbound-connection (node conn onion)
  "Turn an accepted CONN into a peer and start its handshake off the accept
loop. Returns the peer, or NIL when the connection was refused."
  (multiple-value-bind (allowed reason)
      (inbound-connection-allowed-p node (bl.net:connection-host conn) onion)
    (cond
      ((not allowed)
       (log-cat "net" "connection from ~A dropped (~(~A~))"
                (bl.net:connection-host conn) reason)
       (bl.net:close-connection conn)
       nil)
      (t
       (let ((peer (bl.net:make-inbound-peer
                    conn (bl.net:connection-host conn)
                    :inbound-onion onion)))
         (bt:with-lock-held (*inbound-handshake-lock*)
           (incf *inbound-handshakes-in-flight*))
         (bt:make-thread (lambda () (%run-inbound-handshake node peer onion))
                         :name "bitcoin-inbound-handshake")
         peer)))))

(defun run-inbound-listener (node &key (socket (node-listener-socket node)) onion)
  "Accept inbound connections on SOCKET and hand each one to its own handshake
thread, which queues the ready peer for the sync thread via
pending-inbound-peers. Runs until the node stops.

The accept loop does NOT wait for a handshake: Core's does not either
(net.cpp:1854-1858), and ours doing so made every new connection wait out the
previous peer's whole handshake timeout. ONION marks this as the onion-service
listener: its connections arrive from the local Tor daemon, so the peers are
tagged inbound-onion (their true network is :torv3, Core CNode::m_inbound_onion)."
  (loop while (node-running node)
        do (handler-case
               ;; setnetworkactive off: don't accept inbound connections.
               (if (not (node-network-active node))
                   (sleep 1)
                   (let ((conn (bl.net:accept-connection socket :timeout 1)))
                     (when conn
                       ;; Banned/discouraged/backlog admission gate BEFORE any
                       ;; handshake work (Core drops these in
                       ;; CreateNodeFromAcceptedSocket, net.cpp:1801-1813).
                       ;; ONION travels with it because the permission lookup
                       ;; those drops consult must ignore the address of a Tor
                       ;; inbound (net.cpp:1770-1772).
                       (admit-inbound-connection node conn onion))))
             (error (c)
               (log-debug "Inbound accept/handshake error: ~A" c)))))

(defun start-inbound-listener (node bind)
  "Open the listening socket and spawn the accept thread. No-op (logged) if the
port can't be bound."
  (let ((sock (bl.net:open-listener bind (listen-port (node-network node)))))
    (if sock
        (progn
          (setf (node-listener-socket node) sock)
          (setf (node-listener-thread node)
                (bt:make-thread (lambda () (run-inbound-listener node))
                                :name "bitcoin-inbound-listener"))
          ;; Core's line for a bound listening socket (CConnman::BindListenPort,
          ;; net.cpp:3329). feature_port.py reads `Bound to <addr>:<port>' out
          ;; of debug.log to check where -port and -bind actually put the
          ;; socket, and it is the only record an operator has of the same.
          (log-info "Bound to ~A:~D" bind (listen-port (node-network node)))
          (log-info "Listening for inbound peers on ~A:~D"
                    bind (listen-port (node-network node))))
        (log-warn "Inbound listening disabled: could not bind ~A:~D"
                  bind (listen-port (node-network node))))))

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
    (if sock
        (progn
          (setf (node-onion-listener-socket node) sock)
          (setf (node-onion-listener-thread node)
                (bt:make-thread (lambda ()
                                  (run-inbound-listener node :socket sock :onion t))
                                :name "bitcoin-onion-listener"))
          (log-info "Bound to 127.0.0.1:~D" port)
          (log-info "Listening for inbound onion peers on 127.0.0.1:~D" port))
        (log-warn "Onion inbound listening disabled: could not bind 127.0.0.1:~D" port))))
