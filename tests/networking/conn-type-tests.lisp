(in-package #:bitcoin-lisp.tests)

(def-suite :conn-type-tests
  :description "Connection types: block-relay-only and feeler tx-relay gating"
  :in :bitcoin-lisp-tests)

(in-suite :conn-type-tests)

(test peer-ids-start-at-zero
  "Core's CConnman::GetNewNodeId is `nLastNodeId.fetch_add(1)' over a counter
initialised to 0 (net.cpp:3390-3393, net.h:1609): it hands out the value BEFORE
the increment, so a node's FIRST peer is id 0. Ours incremented first and every
id was one too high -- p2p_addrfetch.py:40 and p2p_mutated_blocks.py:77 both
assert `info[0]['id'] == 0' on a node's first peer."
  (let ((bl.net::*peer-id-counter* 0))
    (is (= 0 (bl.net:peer-id (bl.net:make-peer))) "the first peer is id 0")
    (is (= 1 (bl.net:peer-id (bl.net:make-peer))) "the second is id 1")
    (is (= 2 (bl.net:peer-id (bl.net:make-peer))))))

(test peer-conn-type-defaults
  "A freshly-made peer defaults to :inbound; make-inbound-peer keeps it."
  (let ((p (bl.net:make-peer)))
    (is (eq :inbound (bl.net:peer-conn-type p))))
  (let ((ip (bl.net:make-inbound-peer nil "203.0.113.7")))
    (is (eq :inbound (bl.net:peer-conn-type ip)))
    (is (bl.net:peer-inbound ip))))

(test peer-relays-txs-p-by-conn-type
  "Full-relay and inbound peers relay txs; block-relay and feeler peers do not."
  (flet ((relays (type)
           (let ((p (bl.net:make-peer :conn-type type)))
             (bl.net:peer-relays-txs-p p))))
    (is-true (relays :inbound))
    (is-true (relays :outbound-full-relay))
    (is-false (relays :block-relay))
    (is-false (relays :feeler))))

(test version-relay-flag-serializes
  "The version payload's trailing relay byte is 0 for a block-relay/feeler
connection (relay nil) and 1 for a full-relay connection (relay t)."
  (let ((full (bl.ser:make-version-message-bytes :relay t))
        (none (bl.ser:make-version-message-bytes :relay nil)))
    (is (= 1 (aref full (1- (length full)))))
    (is (= 0 (aref none (1- (length none)))))))

(test version-gates-follow-core
  "Core's two VERSION-time gates (net_processing.cpp:3611-3627): an automatic
outbound peer must offer the desirable services — NODE_NETWORK|NODE_WITNESS, or
NODE_NETWORK_LIMITED|NODE_WITNESS once we are near the tip
(GetDesirableServiceFlags :1759-1768) — and every peer must announce at least
MIN_PEER_PROTO_VERSION. Inbound, manual and feeler connections are exempt from
the services gate (CNode::ExpectServicesFromConn)."
  (let ((full (logior bl.ser:+node-network+
                      bl.ser:+node-witness+))
        (limited (logior bl.ser:+node-network-limited+
                         bl.ser:+node-witness+)))
    (is (= 31800 bl.net::+min-peer-proto-version+))
    (is-true (bl.net::has-all-desirable-service-flags-p full nil))
    (is-false (bl.net::has-all-desirable-service-flags-p 0 nil))
    (is-false (bl.net::has-all-desirable-service-flags-p
               bl.ser:+node-network+ nil))   ; no witness
    ;; A limited peer is desirable only near the tip.
    (is-false (bl.net::has-all-desirable-service-flags-p limited nil))
    (is-true (bl.net::has-all-desirable-service-flags-p limited t))
    ;; The gate's guard is Core's ExpectServicesFromConn (net.h:833-847),
    ;; whose switch answers false for INBOUND, MANUAL and FEELER and true for
    ;; OUTBOUND_FULL_RELAY, BLOCK_RELAY and ADDR_FETCH. It is asked at
    ;; net_processing.cpp:3613.
    (flet ((expects (&rest args)
             (bl.net:peer-expects-services-p
              (apply #'bl.net:make-peer args))))
      (is-true (expects :conn-type :outbound-full-relay))
      (is-true (expects :conn-type :block-relay))
      (is-true (expects :conn-type :addr-fetch)
               "an addr-fetch dial is held to the desirable services too")
      (is-false (expects :conn-type :manual))
      (is-false (expects :conn-type :feeler))
      (is-false (expects :conn-type :inbound))
      (is-false (expects :conn-type :outbound-full-relay :inbound t)
                "an inbound connection is exempt whatever its type says"))
    ;; And the eviction predicate stays a DIFFERENT set: Core's
    ;; IsOutboundOrBlockRelayConn (net.h:771-785) is the two automatic
    ;; outbound types only, and reading it as the services guard is what let
    ;; an addr-fetch peer through.
    (flet ((evictable (type)
             (bl.net:peer-outbound-or-block-relay-p
              (bl.net:make-peer :conn-type type))))
      (is-true (evictable :outbound-full-relay))
      (is-true (evictable :block-relay))
      (is-false (evictable :addr-fetch)
                "the two predicates differ exactly here"))))

(test an-addr-fetch-dial-is-refused-for-undesirable-services
  "Core guards the VERSION-time services gate with CNode::ExpectServicesFromConn
(net_processing.cpp:3613), and that switch (net.h:833-847) covers ADDR_FETCH
alongside OUTBOUND_FULL_RELAY and BLOCK_RELAY, exempting only INBOUND, MANUAL
and FEELER. Ours guarded it with IsOutboundOrBlockRelayConn -- the eviction
predicate, which is the two automatic outbound types and nothing else -- so an
addr-fetch dial to a peer offering NODE_WITNESS alone completed its handshake.

p2p_handshake.py:53-64 walks all three connection types against the same three
undesirable service sets and asserts a disconnect for each; the addr-fetch row
was the first one our node failed, and the node's log shows six `does not
offer the expected services' lines where Core writes nine."
  (flet ((handshake (conn-type services)
           ;; A real loopback dial whose far end answers with a version
           ;; offering SERVICES and nothing more.
           (let ((srv (bl.net:open-listener "127.0.0.1" 0)))
             (when srv
               (unwind-protect
                    (let* ((port (usocket:get-local-port srv))
                           (done nil)
                           (server
                             (bt:make-thread
                              (lambda ()
                                ;; An unhandled condition in a test thread
                                ;; drops a non-interactive image into the
                                ;; debugger, which reads as a hung suite.
                                (ignore-errors
                                 (let ((conn (bl.net:accept-connection srv :timeout 10)))
                                   (when conn
                                     (bl.net:send-bytes
                                      conn
                                      (bl.ser:serialize-message
                                       "version"
                                       (bl.ser:make-version-message-bytes
                                        :services services)))
                                     (bl.net:send-bytes conn (bl.ser:make-verack-message))
                                     (loop repeat 100 until done do (sleep 0.05))
                                     (bl.net:close-connection conn)))))
                              :name "test-services-peer")))
                      (sleep 0.2)
                      (let ((peer (bl.net:connect-peer "127.0.0.1" port)))
                        (unwind-protect
                             (when peer
                               ;; PERFORM-HANDSHAKE sets the type itself, and
                               ;; its default would overwrite any set here.
                               (and (bl.net:perform-handshake
                                     peer :conn-type conn-type)
                                    t))
                          (setf done t)
                          (when peer (ignore-errors (bl.net:disconnect-peer peer)))
                          (ignore-errors (bt:join-thread server)))))
                 (bl.net:close-listener srv))))))
    (let ((witness-only bl.ser:+node-witness+)
          (full (logior bl.ser:+node-network+ bl.ser:+node-witness+)))
      ;; The behavioural rows, in the order p2p_handshake.py walks them.
      (is-false (handshake :outbound-full-relay witness-only)
                "an outbound-full-relay dial lacking NODE_NETWORK is refused")
      (is-false (handshake :block-relay witness-only)
                "so is a block-relay-only dial")
      (is-false (handshake :addr-fetch witness-only)
                "and so is an addr-fetch dial -- Core expects services there too")
      ;; The exemptions, and the control that the gate is not simply refusing
      ;; every handshake.
      (is-true (handshake :manual witness-only)
               "a manual (-addnode) peer is exempt")
      (is-true (handshake :feeler witness-only)
               "and so is a feeler")
      (is-true (handshake :addr-fetch full)
               "control: an addr-fetch peer that does offer the services connects"))))
