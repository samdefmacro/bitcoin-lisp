(in-package #:bitcoin-lisp)

;;;; Inbound listening: the accept loop and the onion listener.

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
    (if sock
        (progn
          (setf (node-listener-socket node) sock)
          (setf (node-listener-thread node)
                (bt:make-thread (lambda () (run-inbound-listener node))
                                :name "bitcoin-inbound-listener"))
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
          (log-info "Listening for inbound onion peers on 127.0.0.1:~D" port))
        (log-warn "Onion inbound listening disabled: could not bind 127.0.0.1:~D" port))))
