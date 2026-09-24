(in-package #:bitcoin-lisp.tests)

(def-suite :sync-thread-tests
  :description "The sync thread's between-cycle idle tick (Core's continuous ProcessMessages, bounded)"
  :in :bitcoin-lisp-tests)

(in-suite :sync-thread-tests)

(defun %idle-tick ()
  "One idle tick of the sync thread against BL:*NODE*, as %SYNC-PASS runs it
between two sync cycles. The one internal reach of this file."
  (bl::%sync-idle-tick 1))

(defun %offline-pass ()
  "The sync thread's NO-PEER pass against BL:*NODE* (%SYNC-OFFLINE-ACTIVATION):
activate whatever is on disk, then wait before dialling again."
  (bl::%sync-offline-activation 0))

(test the-no-peer-wait-admits-an-inbound-peer-that-arrives-during-it
  "The sync loop merges the listener's hand-off list at the top of each
iteration, and an iteration with no peers is %SYNC-OFFLINE-ACTIVATION, which
slept five seconds before returning. A node nothing has dialled -- every
functional test's node -- therefore took up to five seconds to show an accepted
peer in getpeerinfo, and that is exactly the budget
p2p_v2_misbehaving.py:143 gives wait_for_new_peer. Core's accepted socket joins
m_nodes at accept and is visible at once (net.cpp:1854-1858).

The wait now merges every second and stops as soon as a peer appears."
  (let ((srv (bl.net:open-listener "127.0.0.1" 0)))
    (is-true srv)
    (when srv
      (unwind-protect
           (let* ((bl:*network* :regtest)
                  (port (usocket:get-local-port srv))
                  (node (make-test-node :network :regtest))
                  (bl:*node* node)
                  (client (bl.net:connect-peer "127.0.0.1" port))
                  (conn (and client (bl.net:accept-connection srv :timeout 10)))
                  (server-peer (and conn (bl.net:make-inbound-peer conn "127.0.0.1"))))
             (is-true client)
             (is-true conn)
             (when server-peer
               (unwind-protect
                    (progn
                      (setf (bl:node-running node) t)
                      ;; The listener's hand-off, as ADMIT-INBOUND-CONNECTION
                      ;; does it -- at accept, with the handshake still running.
                      (push server-peer (bl:node-pending-inbound-peers node))
                      (is (null (bl:node-peers node)) "control: nothing admitted yet")
                      (%offline-pass)
                      (is-true (member server-peer (bl:node-peers node))
                               "the no-peer wait must admit a peer that arrives during it")
                      (is (null (bl:node-pending-inbound-peers node))))
                 (setf (bl:node-running node) nil)
                 (bl.net:disconnect-peer server-peer)
                 (bl.net:disconnect-peer client))))
        (bl.net:close-listener srv)))))

(test idle-tick-admits-a-pending-inbound-peer-and-answers-it
  "An inbound peer the listener hands over during the sync thread's 30-second
wait must be admitted and read by the NEXT idle tick, not by the next cycle.
Core has no hand-off: an accepted socket joins m_nodes at once
(net.cpp:1854-1858) and ProcessMessages runs on it continuously.

Before the fix the pump iterated node-peers alone, so a peer parked in
pending-inbound-peers sat unread until the cycle's merge -- every functional
test's python peer waited up to 30 s for its first reply. Control: the same
peer placed in node-peers directly was answered by one tick."
  (let ((srv (bl.net:open-listener "127.0.0.1" 0)))
    (is-true srv)
    (when srv
      (unwind-protect
           (let* ((bl:*network* :regtest)
                  (port (usocket:get-local-port srv))
                  (node (make-test-node :network :regtest))
                  (bl:*node* node)
                  (client (bl.net:connect-peer "127.0.0.1" port))
                  (conn (and client (bl.net:accept-connection srv :timeout 10)))
                  (server-peer (and conn (bl.net:make-inbound-peer conn "127.0.0.1"))))
             (is-true client)
             (is-true conn)
             (when server-peer
               (unwind-protect
                    (progn
                      (setf (bl:node-running node) t
                            (bl.net:peer-state server-peer) :ready
                            (bl.net:peer-state client) :ready)
                      ;; The listener's hand-off, as run-inbound-listener does it.
                      (push server-peer (bl:node-pending-inbound-peers node))
                      (is (null (bl:node-peers node)) "control: nothing admitted yet")
                      (bl.net:send-message client (bl.ser:make-ping-message 42))
                      (sleep 0.2)
                      (is-true (%idle-tick)
                               "a tick that admitted a peer ends the wait, so the sync pass asks it for headers now")
                      (is-true (member server-peer (bl:node-peers node))
                               "the tick must admit the pending inbound peer")
                      (is (null (bl:node-pending-inbound-peers node)))
                      (is (equal "pong" (next-message-within client 3))
                          "the same tick must read and answer the peer's ping"))
                 (setf (bl:node-running node) nil)
                 (bl.net:disconnect-peer server-peer)
                 (bl.net:disconnect-peer client))))
        (bl.net:close-listener srv)))))

(test idle-tick-drains-a-queued-addconnection
  "An addconnection request is dialed by the next idle tick, not a cycle
later: Core's AddConnection dials on the RPC thread itself (net.cpp:1871-1907)
and the functional framework's add_outbound_p2p_connection waits on
getpeerinfo for the result. The dial here targets a port nobody listens on,
so what is asserted is the drive site -- the queue is consumed by one tick --
not the handshake, which inbound-listening-tests covers."
  (let* ((probe (bl.net:open-listener "127.0.0.1" 0))
         (port (usocket:get-local-port probe)))
    (bl.net:close-listener probe)
    (let* ((bl:*network* :regtest)
           (node (make-test-node :network :regtest))
           (bl:*node* node)
           (bl:*pending-test-connections* '()))
      (unwind-protect
           (progn
             (setf (bl:node-running node) t)
             (push (list (format nil "127.0.0.1:~D" port) :outbound-full-relay nil)
                   bl:*pending-test-connections*)
             (is (= 1 (length bl:*pending-test-connections*)) "control: one request queued")
             (%idle-tick)
             (is (null bl:*pending-test-connections*)
                 "one idle tick must consume the addconnection queue"))
        (setf (bl:node-running node) nil)))))

(test idle-tick-with-nothing-pending-keeps-waiting
  "Control for the admitted-peer exit above: a tick on a node with no peer
pending, none queued to dial and no headers arriving returns NIL, so the
30-second wait is not cut short for no reason."
  (let* ((bl:*network* :regtest)
         (node (make-test-node :network :regtest))
         (bl:*node* node)
         (bl:*pending-test-connections* '()))
    (unwind-protect
         (progn
           (setf (bl:node-running node) t)
           (is-false (%idle-tick)))
      (setf (bl:node-running node) nil))))

(test fixed-seeds-follow-cores-fallback-rule
  "Core ThreadOpenConnections (net.cpp:2562-2640) adds the chain's fixed seeds
ONCE, for the reachable networks the address book has nothing for: at once
when no other address source exists (-dnsseed=0, no -seednode, no -addnode),
otherwise after 60 s of the mockable clock; -fixedseeds=0 only logs. The node
used to merge them into its first dial list whenever that list had fewer than
eight /16 groups, logged none of Core's lines, and never added them to the
address book (feature_config_args.py:320-366)."
  (let* ((t0 1700000000)
         (bl:*network* :testnet4)
         (bl.ser:*mock-time* t0)
         (bl.net:*reachable-networks* '(:ipv4 :ipv6))
         (bl:*dns-seed-enabled* nil)
         (bl:*seed-nodes* '())
         (bl:*use-addrman-outgoing* t)
         (bl:*fixed-seeds-enabled* t)
         (seeds (length (bl.chain:chain-params-fixed-seeds
                         (bl.chain:find-chain-params :testnet4)))))
    (flet ((fresh-node ()
             (let ((node (make-test-node :network :testnet4)))
               (setf (bl:node-address-book node) (bl.net:make-address-book))
               node))
           (logged-p (lines text)
             (some (lambda (l) (search text (princ-to-string l))) lines)))
      ;; No other source: added on the first pass, and only once.
      (let* ((node (fresh-node))
             (added nil)
             (lines (capture-log-lines
                     (lambda ()
                       (bl:start-fixed-seed-fallback)
                       (setf added (bl:maybe-add-fixed-seeds node))))))
        (is (logged-p lines "Adding fixed seeds as -dnsseed=0"))
        (is (eql seeds added))
        (is (plusp (bl.net:address-book-count (bl:node-address-book node))))
        (is (null (bl:maybe-add-fixed-seeds node))))
      ;; DNS seeding on: nothing until the MOCK clock passes 60 s.
      (let ((bl:*dns-seed-enabled* t)
            (node (fresh-node)))
        (bl:start-fixed-seed-fallback)
        (is (null (bl:maybe-add-fixed-seeds node)))
        (setf bl.ser:*mock-time* (+ t0 60))
        (is (null (bl:maybe-add-fixed-seeds node)))
        (setf bl.ser:*mock-time* (+ t0 61))
        (let ((lines (capture-log-lines
                      (lambda () (is (eql seeds (bl:maybe-add-fixed-seeds node)))))))
          (is (logged-p lines "Adding fixed seeds as 60 seconds have passed"))
          (is (logged-p lines (format nil "Added ~D fixed seeds" seeds))))
        (setf bl.ser:*mock-time* t0))
      ;; An -addnode is another source, so the immediate branch is closed.
      (let ((node (fresh-node)))
        (setf (bl:node-added-nodes node) (list "fakenodeaddr"))
        (bl:start-fixed-seed-fallback)
        (is (null (bl:maybe-add-fixed-seeds node))))
      ;; Every reachable network already has an address: nothing to add.
      (let ((node (fresh-node))
            (bl.net:*reachable-networks* '(:ipv4)))
        (bl.net:address-book-add (bl:node-address-book node)
                                 (bl.net:make-peer-address
                                  :net :ipv4 :ip (bl.net:string-to-ip-bytes "8.8.8.8")
                                  :port 48333 :services 0 :last-seen t0))
        (bl:start-fixed-seed-fallback)
        (is (null (bl:maybe-add-fixed-seeds node))))
      ;; -fixedseeds=0: Core's one line, and never an addition.
      (let* ((bl:*fixed-seeds-enabled* nil)
             (node (fresh-node))
             (lines (capture-log-lines #'bl:start-fixed-seed-fallback)))
        (is (logged-p lines "Fixed seeds are disabled"))
        (is (null (bl:maybe-add-fixed-seeds node)))))))

(test start-up-logs-set-network-active-either-way
  "Core's CConnman constructor calls SetNetworkActive(-networkactive), which
logs `SetNetworkActive: true' or `: false' before anything else
(net.cpp:3356, :3387); feature_config_args.py:270-290 waits for the line at
every start. Ours logged only the disabled case, in words of its own."
  (dolist (active '(t nil))
    (let* ((node (make-test-node :network :regtest))
           (lines (capture-log-lines
                   (lambda () (bl:apply-initial-network-active node active)))))
      (is (eq active (bl:node-network-active node)))
      (is (some (lambda (l)
                  (search (format nil "SetNetworkActive: ~:[false~;true~]" active)
                          (princ-to-string l)))
                lines)))))

(test connect-logs-what-it-overrides
  "Under -connect Core notes that -seednode is ignored (when there are
targets) and that an explicit -dnsseed=1 is ignored under -proxy
(init.cpp:2214-2229); feature_config_args.py:378-384 waits for both."
  (flet ((lines (targets seednode dns proxy)
           (let ((bl:*dns-seed-enabled* dns)
                 (bl.net:*proxy* (and proxy (bl.net:make-proxy :host "127.0.0.1" :port 1))))
             (mapcar #'princ-to-string
                     (capture-log-lines
                      (lambda () (bl:log-connect-overrides targets seednode))))))
         (has (lines text) (some (lambda (l) (search text l)) lines)))
    (let ((l (lines '("fakeaddress1") '("fakeaddress2") nil nil)))
      (is (has l "-seednode is ignored when -connect is used"))
      (is (not (has l "-dnsseed is ignored"))))
    (is (not (has (lines '() '("fakeaddress2") nil nil) "-seednode is ignored"))
        "-connect=0 ignores nothing: there is no -connect target")
    (is (has (lines '("fakeaddress1") '() t t)
             "-dnsseed is ignored when -connect is used and -proxy is specified"))
    (is (not (has (lines '("fakeaddress1") '() t nil) "-dnsseed is ignored")))))

(test idle-tick-drops-a-handshake-that-outlived-peertimeout-on-the-mock-clock
  "Core evaluates InactivityCheck on every socket-handler pass
(SocketHandlerConnected, net.cpp:2218) against GetTime -- the MOCKABLE clock --
and m_connected is that clock at accept (net.cpp:3982), so a test that freezes
the clock, opens a connection that never finishes its handshake and then bumps
the clock past -peertimeout sees the peer dropped at once:
p2p_v2_misbehaving.py:155 and p2p_timeouts.py:98 give the disconnect ONE
second. Ours judged the gate on the process's real clock, and ran it only from
the once-per-pass MAINTAIN-PEERS sweep, up to 30 s later.

Control: with the clock left at the connect time the same tick keeps the peer."
  (let* ((bl:*network* :regtest)
         (node (make-test-node :network :regtest))
         (bl:*node* node)
         (t0 1780000000)
         (bl.ser:*mock-time* t0)
         (bl:*handshake-timeout-seconds* 3)
         (peer (bl.net:make-peer :state :handshaking :address "203.0.113.9")))
    (unwind-protect
         (progn
           (setf (bl:node-running node) t)
           (push peer (bl:node-peers node))
           (%idle-tick)
           (is-true (member peer (bl:node-peers node))
                    "control: inside -peertimeout on the mock clock the peer stays")
           (setf bl.ser:*mock-time* (+ t0 4))
           (%idle-tick)
           (is-false (member peer (bl:node-peers node))
                     "one tick after the mock clock passes -peertimeout the unfinished handshake is dropped")
           (is (eq :disconnected (bl.net:peer-state peer))))
      (setf (bl:node-running node) nil))))

(test idle-tick-walks-the-chain-sync-eviction-ladder
  "Core calls ConsiderEviction from SendMessages on every message-handler pass
(net_processing.cpp:6157-6159). p2p_outbound_eviction.py:46-56 jumps mocktime
past CHAIN_SYNC_TIMEOUT, pings, and immediately jumps it past
HEADERS_RESPONSE_TIME: the probe must go out between the two jumps, and the
disconnect must follow the second within the framework's wait. Ours walked
the ladder only from MAINTAIN-PEERS, once per 30-second sync pass, so the probe
was stamped after the second jump and its deadline never passed.

A peer whose probe has already gone unanswered past its deadline is dropped by
ONE idle tick, with Core's line."
  (let* ((bl:*network* :regtest)
         (node (make-test-node :network :regtest))
         (bl:*node* node)
         (peer (bl.net:make-peer :state :ready :address "203.0.113.10"
                                 :conn-type :outbound-full-relay
                                 :chain-sync-timeout 1
                                 :chain-sync-sent-getheaders t
                                 :headers-sync-started t)))
    (unwind-protect
         (progn
           (setf (bl:node-running node) t)
           (push peer (bl:node-peers node))
           (is-true (bl.net:peer-outbound-or-block-relay-p peer)
                    "control: an automatic outbound peer is a candidate")
           (let ((lines (capture-log-lines #'%idle-tick)))
             (is-true (find "Outbound peer has old chain" lines :test #'search)
                      "one idle tick must walk the ladder to the disconnect: ~S" lines)))
      (setf (bl:node-running node) nil))))

(test an-addconnection-feeler-is-dropped-once-its-handshake-is-done
  "Core's VERSION handler disconnects a feeler as soon as the version is in:
\"feeler connection completed, disconnecting peer=N\"
(net_processing.cpp:3807-3811). The addconnection RPC is how a test asks for
one (p2p_handshake.py:97-98 waits for the line and for getpeerinfo to empty);
ours kept an addconnection feeler as an ordinary peer. CONNECT-PEER and
PERFORM-HANDSHAKE are stubbed so the idle tick's real dial path runs up to a
completed handshake."
  (let* ((bl:*network* :regtest)
         (node (make-test-node :network :regtest))
         (bl:*node* node)
         (bl:*pending-test-connections* (list (list "203.0.113.20:18444" :feeler nil)))
         (real-connect (fdefinition 'bl.net:connect-peer))
         (real-handshake (fdefinition 'bl.net:perform-handshake))
         (enabled (bl.log:log-category-enabled-p "net"))
         (lines nil))
    (unwind-protect
         (progn
           (setf (bl:node-running node) t
                 (fdefinition 'bl.net:connect-peer)
                 (lambda (host &optional port &rest more)
                   (declare (ignore port more))
                   (bl.net:make-peer :address host :state :connected))
                 (fdefinition 'bl.net:perform-handshake)
                 (lambda (peer &rest args)
                   (setf (bl.net:peer-state peer) :ready
                         (bl.net:peer-conn-type peer) (getf args :conn-type))
                   t))
           (bl.log:enable-log-category "net")
           (setf lines (capture-log-lines #'%idle-tick)))
      (setf (fdefinition 'bl.net:connect-peer) real-connect
            (fdefinition 'bl.net:perform-handshake) real-handshake
            (bl:node-running node) nil)
      (unless enabled (bl.log:disable-log-category "net")))
    (is-true (find "feeler connection completed, disconnecting peer=" lines :test #'search)
             "Core's line once the feeler's handshake is done: ~S" lines)
    (is (null (bl:node-peers node)) "and the feeler never joins the peer set")))

(test the-no-peer-wait-dials-a-queued-addconnection
  "A node with no peer sits in %SYNC-OFFLINE-ACTIVATION's five-second wait,
and an addconnection that arrives then was dialed only after it -- Core's
AddConnection dials on the RPC thread itself (net.cpp:1871-1907).
p2p_handshake.py:100-104 asks a peerless node to connect to itself and waits
two seconds for the self-connection line. The wait now drains the RPC-queued
dials every second, like the hand-off list. CONNECT-PEER and
PERFORM-HANDSHAKE are stubbed so the dial completes."
  (let* ((bl:*network* :regtest)
         (node (make-test-node :network :regtest))
         (bl:*node* node)
         (bl:*pending-test-connections*
           (list (list "203.0.113.21:18444" :outbound-full-relay nil)))
         (real-connect (fdefinition 'bl.net:connect-peer))
         (real-handshake (fdefinition 'bl.net:perform-handshake))
         (started (get-internal-real-time)))
    (unwind-protect
         (progn
           (setf (bl:node-running node) t
                 (fdefinition 'bl.net:connect-peer)
                 (lambda (host &optional port &rest more)
                   (declare (ignore port more))
                   (bl.net:make-peer :address host :state :connected))
                 (fdefinition 'bl.net:perform-handshake)
                 (lambda (peer &rest args)
                   (declare (ignore args))
                   (setf (bl.net:peer-state peer) :ready)
                   t))
           (%offline-pass))
      (setf (fdefinition 'bl.net:connect-peer) real-connect
            (fdefinition 'bl.net:perform-handshake) real-handshake
            (bl:node-running node) nil))
    (is (null bl:*pending-test-connections*) "the queued dial was taken")
    (is (= 1 (length (bl:node-peers node))) "and the peer it made is admitted")
    (is (< (- (get-internal-real-time) started)
           (* 4 internal-time-units-per-second))
        "within the wait, not after it")))

(test an-outbound-peer-is-published-while-it-handshakes
  "Core's CNode joins m_nodes when OpenNetworkConnection opens the socket
(net.cpp:2981-2986), before any version is exchanged, and AddConnection returns
then (net.cpp:1871-1907). The functional framework calls addconnection FROM its
own network thread, which must then answer our version: an RPC that waited for
the whole handshake deadlocked against it until its bound ran out (ten seconds
per p2p_add_connections.py connection). So the dial publishes the peer and
marks the RPC's request done BEFORE the handshake, and withdraws the peer if
the handshake fails. PERFORM-HANDSHAKE is stubbed to observe that moment and
then refuse."
  (let* ((bl:*network* :regtest)
         (node (make-test-node :network :regtest))
         (bl:*node* node)
         (done (list nil))
         (bl:*pending-test-connections*
           (list (list "203.0.113.22:18444" :outbound-full-relay nil done)))
         (real-connect (fdefinition 'bl.net:connect-peer))
         (real-handshake (fdefinition 'bl.net:perform-handshake))
         (seen nil))
    (unwind-protect
         (progn
           (setf (bl:node-running node) t
                 (fdefinition 'bl.net:connect-peer)
                 (lambda (host &optional port &rest more)
                   (declare (ignore port more))
                   (bl.net:make-peer :address host :state :connected))
                 (fdefinition 'bl.net:perform-handshake)
                 (lambda (peer &rest args)
                   (declare (ignore args))
                   (setf seen (list (and (member peer (bl:node-peers node)) t)
                                    (car done)))
                   nil))
           (%idle-tick))
      (setf (fdefinition 'bl.net:connect-peer) real-connect
            (fdefinition 'bl.net:perform-handshake) real-handshake
            (bl:node-running node) nil))
    (is (equal '(t t) seen)
        "during the handshake the peer is listed and the RPC already released: ~S" seen)
    (is (null (bl:node-peers node)) "a failed handshake withdraws it")))

(test the-idle-wait-answers-a-ping-as-soon-as-it-arrives
  "Core's message handler sleeps at most 100 ms and is woken the moment a
message completes (condMsgProc.wait_until, net.cpp:3157, ended by
WakeMessageHandler, :2246-2253), so a peer that waits for each reply gets it in
milliseconds. Our idle wait slept a fixed 200 ms tick before every pump, so
each request/reply round trip cost a tick: the functional framework's
send_and_ping pays one per message, and twenty of them took four seconds in
p2p_tx_download.py:130's announcement loop, which is what moved its fetch past
the sync_mempools deadline.

Ten sequential ping/pong round trips through the running idle wait must take
well under the two seconds ten ticks cost. Control: every pong arrives."
  (let ((srv (bl.net:open-listener "127.0.0.1" 0)))
    (is-true srv)
    (when srv
      (unwind-protect
           (let* ((bl:*network* :regtest)
                  (port (usocket:get-local-port srv))
                  (node (make-test-node :network :regtest))
                  (client (bl.net:connect-peer "127.0.0.1" port))
                  (conn (and client (bl.net:accept-connection srv :timeout 10)))
                  (server-peer (and conn (bl.net:make-inbound-peer conn "127.0.0.1")))
                  (waiter nil))
             (is-true server-peer)
             (when server-peer
               (unwind-protect
                    (progn
                      (setf (bl:node-running node) t
                            (bl.net:peer-state server-peer) :ready
                            (bl.net:peer-state client) :ready
                            (bl:node-peers node) (list server-peer))
                      (setf waiter
                            (bt:make-thread
                             (lambda ()
                               (let ((bl:*node* node))
                                 (ignore-errors
                                  (loop while (bl:node-running node)
                                        do (bl:sync-idle-wait)))))
                             :name "test-idle-wait"))
                      (sleep 0.3)
                      (let ((pongs 0)
                            (t0 (get-internal-real-time)))
                        (dotimes (i 10)
                          (bl.net:send-message client (bl.ser:make-ping-message (1+ i)))
                          (loop with deadline = (+ (get-internal-real-time)
                                                   (* 3 internal-time-units-per-second))
                                while (< (get-internal-real-time) deadline)
                                do (let ((command (bl.net:receive-message client)))
                                     (when (equal command "pong")
                                       (incf pongs)
                                       (return)))
                                   (sleep 0.001)))
                        (let ((seconds (/ (- (get-internal-real-time) t0)
                                          internal-time-units-per-second)))
                          (is (= 10 pongs) "control: every ping was answered")
                          (is (< seconds 1)
                              "ten ping round trips through the idle wait took ~,2F s"
                              (float seconds)))))
                 (setf (bl:node-running node) nil)
                 (when waiter (bt:join-thread waiter))
                 (bl.net:disconnect-peer server-peer)
                 (bl.net:disconnect-peer client))))
        (bl.net:close-listener srv)))))

;;;; The threads Core names in its log (util/thread.cpp TraceThread)

(defun %poll-until (predicate seconds)
  "Poll PREDICATE every tenth of a second for up to SECONDS; its last value."
  (loop repeat (round (* seconds 10))
        thereis (funcall predicate)
        do (sleep 0.1)
        finally (return (funcall predicate))))

(test the-sync-thread-is-msghand-and-opencon-when-it-dials
  "One thread does the jobs of Core's ThreadMessageHandler and, when the node
picks its own outbound peers, ThreadOpenConnections (net.cpp:3539-3548), and
logs both names: feature_init.py:83 interrupts start-up on `msghand thread
start', feature_config_args.py:305 waits for `opencon thread start'. Under
-connect=0 Core starts no opencon thread (net.cpp:3539), so no line either."
  (let* ((loop-fn 'bl::%sync-thread-loop)
         (main-fn 'bl::%sync-thread-main)
         (outgoing 'bl::*use-addrman-outgoing*)
         (real (fdefinition loop-fn))
         (ran 0))
    (unwind-protect
         (progn
           (setf (fdefinition loop-fn)
                 (lambda (max-peers) (declare (ignore max-peers)) (incf ran)))
           (let ((dialing (progv (list outgoing) '(t)
                            (capture-log-lines (lambda () (funcall main-fn 8)))))
                 (silent (progv (list outgoing 'bl::*connect-nodes*) '(nil nil)
                           (capture-log-lines (lambda () (funcall main-fn 8))))))
             (is (= 2 ran) "the loop runs either way")
             (flet ((at (text lines) (position text lines :test #'search)))
               (is-true (at "msghand thread start" dialing))
               (is-true (at "opencon thread start" dialing))
               (is (< (at "msghand thread start" dialing) (at "opencon thread start" dialing)))
               (is-true (at "msghand thread exit" dialing))
               (is-true (at "msghand thread start" silent))
               (is-false (at "opencon thread start" silent)
                         "-connect=0 opens nothing, so there is no opencon thread"))))
      (setf (fdefinition loop-fn) real))))

(test the-scheduler-thread-closes-the-log-rate-window
  "Core's scheduler thread (init.cpp:1452-1457) runs the log rate limiter's
reset every window (init.cpp:1475-1479): with the window already elapsed, the
running scheduler reopens it within its one-second tick, with no log line
needed to trigger it, and stops when asked."
  (let ((saved-start bl.log:*log-rate-window-start*)
        (saved-limit bl.log:*log-rate-limit*)
        (node (bl:make-node)))
    (unwind-protect
         (progn
           (setf bl.log:*log-rate-limit* t
                 bl.log:*log-rate-window-start* 0)
           (bl:start-scheduler-thread node)
           (let ((thread bl:*scheduler-thread*))
             (is (equal "bitcoin-scheduler" (bt:thread-name thread)))
             (is-true (%poll-until (lambda () (plusp bl.log:*log-rate-window-start*)) 3)
                      "the scheduler closed the elapsed window by itself")
             (bl:stop-scheduler-thread)
             (is-false (bt:thread-alive-p thread))))
      (bl:stop-scheduler-thread)
      (setf bl.log:*log-rate-window-start* saved-start
            bl.log:*log-rate-limit* saved-limit))))

(test the-addcon-thread-queues-a-missing-added-node
  "Core's ThreadOpenAddedConnections (net.cpp:2969-2997) on a thread of its
own, `addcon' (net.cpp:3529-3530): an added node that is not connected is
handed to the sync thread's dial queue within Core's two-second pass, once, and
the thread ends when the node stops running."
  (let ((node (bl:make-node)))
    (setf (bl:node-running node) t
          (bl:node-added-nodes node) (list "203.0.113.9:18444"))
    (unwind-protect
         (progn
           (bl:start-addcon-thread node)
           (let ((thread bl:*addcon-thread*))
             (is (equal "bitcoin-addcon" (bt:thread-name thread)))
             (is-true (%poll-until (lambda () (bl:node-pending-onetry node)) 3))
             (is (equal '(("203.0.113.9:18444" . t)) (bl:node-pending-onetry node))
                 "queued once, as a v2-capable manual dial")
             (setf (bl:node-running node) nil)
             (bl:stop-addcon-thread)
             (is-false (bt:thread-alive-p thread))))
      (setf (bl:node-running node) nil)
      (bl:stop-addcon-thread))))

(defclass %named-test-index () ()
  (:documentation "An index that is only its name, for the index-thread test."))

(defmethod bl.store:index-name ((index %named-test-index)) "txindex")

(test an-index-catches-up-on-a-thread-named-after-it
  "Core BaseIndex::StartBackgroundSync (index/base.cpp:453-459) syncs each
index on a thread named after it; feature_init.py:79-82 interrupts start-up on
`txindex thread start' and its siblings. The catch-up's value comes back, and
what it signals is signalled again on the caller's thread."
  (let ((real (fdefinition 'bl:catch-up-index))
        (index (make-instance '%named-test-index))
        (where nil))
    (unwind-protect
         (progn
           (setf (fdefinition 'bl:catch-up-index)
                 (lambda (node index)
                   (declare (ignore node index))
                   (setf where (bt:thread-name (bt:current-thread)))
                   7))
           (let* ((value nil)
                  (lines (capture-log-lines
                          (lambda ()
                            (setf value (bl:start-index-background-sync (bl:make-node) index))))))
             (is (= 7 value))
             (is (equal "bitcoin-txindex" where) "the catch-up ran on its own thread")
             (is-true (find "txindex thread start" lines :test #'search))
             (is-true (find "txindex thread exit" lines :test #'search)))
           (setf (fdefinition 'bl:catch-up-index)
                 (lambda (node index) (declare (ignore node index)) (error "index boom")))
           (is (search "index boom"
                       (handler-case (progn (bl:start-index-background-sync (bl:make-node) index)
                                            "")
                         (error (e) (princ-to-string e))))))
      (setf (fdefinition 'bl:catch-up-index) real))))

(test seed-nodes-go-to-the-addr-fetch-queue-on-cores-timer
  "Core's ThreadOpenConnections (net.cpp:2565-2586, :2690-2695): with an EMPTY
address book the first -seednode is queued for an addr-fetch dial at once
(`Empty addrman, adding seednode'); with addresses to try, the next one is
queued only once 10 s of the MOCKABLE clock pass without two full-relay
outbound peers (`Couldn't connect to peers from addrman after 10 seconds').
Ours dialed every -seednode at start-up; p2p_seednode.py:33 and :52 wait for
Core's lines. The queued seed is dialed as an addr-fetch connection, which
the `trying' line names."
  (let* ((t0 1700000000)
         (bl.ser:*mock-time* t0)
         (bl:*seed-nodes* '("127.0.0.1:1"))
         (bl:*use-addrman-outgoing* t)
         (bl.net:*v2-transport-enabled* nil)) ; the framework's -v2transport=0
    (flet ((fresh-node ()
             (let ((node (make-test-node :network :regtest)))
               (setf (bl:node-address-book node) (bl.net:make-address-book)
                     (bl:node-network-active node) t)
               node))
           (seed-pass (node)
             (nth-value 1 (log-text-of "net" (lambda () (bl:connect-seed-nodes node))))))
      (let ((node (fresh-node)))
        (bl:start-fixed-seed-fallback)
        (let ((text (seed-pass node)))
          (is (search "Empty addrman, adding seednode (127.0.0.1:1) to addrfetch" text))
          (is (search "trying v1 connection (addr-fetch) to 127.0.0.1:1" text)
              "the queued seed is dialed as an addr-fetch connection")))
      (let ((node (fresh-node)))
        (bl.net:address-book-add (bl:node-address-book node)
                                 (bl.net:make-peer-address
                                  :ip (bl.net:ipv4-to-mapped-ipv6 8 8 8 8) :port 8333
                                  :services 1 :last-seen t0))
        (bl:start-fixed-seed-fallback)
        (is (not (search "seednode" (seed-pass node))) "a non-empty book tries addrman first")
        (setf bl.ser:*mock-time* (+ t0 10))
        (is (not (search "seednode" (seed-pass node))))
        (setf bl.ser:*mock-time* (+ t0 11))
        (seed-pass node)                     ; the timer fires: queued next pass
        (is (search "Couldn't connect to peers from addrman after 10 seconds. Adding seednode (127.0.0.1:1) to addrfetch"
                    (seed-pass node)))))))

(test dns-seeds-wait-and-log-as-cores-thread-does
  "Core's ThreadDNSAddressSeed (net.cpp:2255-2391): every seed tried says
`Loading addresses from DNS seed <seed>', a name proxy included (the seed is
then queued as an addr-fetch for the proxy to resolve); an empty address book
queries at once; a non-empty one first says `Waiting 11 seconds before
querying DNS seeds.' and, with two full-relay outbound peers up by then,
`P2P peers available. Skipped DNS seeding.' p2p_dns_seeds.py:36, :62, :108
wait for each; ours resolved every seed at once without any of them."
  (let ((bl.net:*proxy* (bl.net:make-proxy :host "127.0.0.1" :port 1))
        (bl.net:*dns-seeds* '("dummySeed.invalid."))
        (bl:*seed-nodes* '())
        (bl:*force-dns-seed* nil))
    (let ((node (make-test-node :network :regtest)))
      (setf (bl:node-address-book node) (bl.net:make-address-book)
            (bl:node-running node) t
            (bl:node-network-active node) t)
      (let ((text (nth-value 1 (log-text-of "net" (lambda () (bl:dns-address-seed node))))))
        (is (search "Loading addresses from DNS seed dummySeed.invalid." text))
        (is (search "0 addresses found from DNS seeds" text)))
      ;; A book with an address waits first; two ready full-relay peers end it.
      (bl.net:address-book-add (bl:node-address-book node)
                               (bl.net:make-peer-address
                                :ip (bl.net:ipv4-to-mapped-ipv6 8 8 8 8) :port 8333
                                :services 1 :last-seen 1700000000))
      (setf (bl:node-peers node)
            (loop repeat 2 collect (bl.net:make-peer :address "9.9.9.9" :state :ready
                                                     :conn-type :outbound-full-relay)))
      (let ((text (nth-value 1 (log-text-of "net" (lambda () (bl:dns-address-seed node))))))
        (is (search "Waiting 11 seconds before querying DNS seeds." text))
        (is (search "P2P peers available. Skipped DNS seeding." text))
        (is (not (search "Loading addresses" text)))))))

(test the-ping-clock-is-the-mockable-one
  "Core stamps m_ping_start and measures pingwait, the round trip and the
two-minute interval on GetTime<microseconds>(), the MOCKABLE clock
(net_processing.cpp:5487-5510, GetNodeStateStats). p2p_ping.py:57 moves
setmocktime three seconds and expects pingwait 3; ours measured on the real
clock and reported milliseconds."
  (let* ((t0 1700000000)
         (bl.ser:*mock-time* t0)
         (peer (bl.net:make-peer :state :ready)))
    (bl.net:check-peer-health peer)       ; never pinged: pings now
    (is-true (bl.net:peer-ping-nonce peer))
    (is (= (* t0 1000000) (bl.net:peer-last-ping-time peer))
        "the ping is stamped with the mock time, in microseconds")
    (setf bl.ser:*mock-time* (+ t0 121))
    (is (eq :ok (bl.net:check-peer-health peer))
        "an outstanding ping is not replaced")
    ;; TIMEOUT_INTERVAL later, on the same clock, with Core's %f line
    ;; (net_processing.cpp:5495) that p2p_ping.py:112 reads.
    (setf (bl.net:peer-connected-at peer) (- t0 3600)
          bl.ser:*mock-time* (+ t0 1201))
    (multiple-value-bind (verdict text)
        (log-text-of "net" (lambda () (bl.net:check-peer-health peer)))
      (is (eq :disconnect verdict))
      (is (search "ping timeout: 1201.000000s" text)))))
