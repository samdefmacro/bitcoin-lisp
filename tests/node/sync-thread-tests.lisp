(in-package #:bitcoin-lisp.tests)

(def-suite :sync-thread-tests
  :description "The sync thread's between-cycle idle tick (Core's continuous ProcessMessages, bounded)"
  :in :bitcoin-lisp-tests)

(in-suite :sync-thread-tests)

(defun %idle-tick ()
  "One idle tick of the sync thread against BL:*NODE*, as %SYNC-PASS runs it
between two sync cycles. The one internal reach of this file."
  (bl::%sync-idle-tick 1))

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
             (push (cons (format nil "127.0.0.1:~D" port) :outbound-full-relay)
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
