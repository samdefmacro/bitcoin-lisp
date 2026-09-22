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
