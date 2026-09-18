(in-package #:bitcoin-lisp.tests)

;;; Inbound listening tests.
;;;
;;; End-to-end over loopback: open a listener, dial it from a client, and assert
;;; both sides complete the version handshake — the inbound side via
;;; perform-inbound-handshake (receive version first), the outbound side via the
;;; existing perform-handshake. Both peers must reach :ready, and the accepted
;;; peer must be flagged inbound.

(in-suite :inbound-listening-tests)

(test a-peer-that-sent-no-version-reports-cores-defaults
  "An accepted peer is published before its handshake (Core's CNode joins
m_nodes in CreateNodeFromAcceptedSocket, net.cpp:1854-1858), so getpeerinfo
answers for a peer that has said nothing -- rpc_net.py:137-183 opens exactly
such a connection and compares the whole row. Three of its fields came from
defaults that were not Core's:

  * startingheight: Core's Peer::m_starting_height is {-1}
    (net_processing.cpp:277), `the peer has not told us'. Ours was 0, i.e.
    `genesis'.
  * relaytxes / last_inv_sequence / inv_to_send / minfeefilter: Core reads
    these off Peer::TxRelay, which only the VERSION handler creates
    (:3681-3696); with no object GetNodeStateStats fills in false and zeroes
    (:1819-1829). PEER-TX-RELAY-P answers the OTHER question -- would we relay
    to this peer -- and says yes for a version-less peer on purpose, because
    Core's pre-70001 fRelay default is true. Reading it here reported
    relaytxes true and last_inv_sequence 1 for a peer that had sent nothing.
  * network: 127.0.0.1 is NET_UNROUTABLE to Core's GetNetClass. The renderer
    asked addrman's DIAL predicate, which keeps loopback routable on purpose,
    and answered `ipv4'."
  (let ((fresh (bl.net:make-peer :address "127.0.0.1" :state :connected
                                 :inbound t)))
    ;; Behavioural first, in pre-existing names only.
    (is (= -1 (bl.net:peer-start-height fresh))
        "a peer that has sent no version has told us no starting height")
    (is-true (bl.net:peer-tx-relay-p fresh)
        "control: we WOULD relay to it -- Core's pre-70001 fRelay default")
    ;; Then the names this fix introduces.
    (is-false (bl.net:peer-tx-relay-state-p fresh)
              "but it has no Peer::TxRelay yet, so getpeerinfo reports zeroes")
    (multiple-value-bind (net bytes)
        (bl.net:parse-network-address "127.0.0.1")
      (is-true (bl.net:address-routable-p bytes net)
               "control: loopback stays dialable for regtest")
      (is-false (bl.net:address-publicly-routable-p bytes net)
                "loopback is not a publicly routable network"))
    (multiple-value-bind (net bytes)
        (bl.net:parse-network-address "8.8.8.8")
      (is-true (bl.net:address-publicly-routable-p bytes net)
               "control: a globally routable address still is"))))

(test inbound-handshake-loopback
  (let ((srv (bl.net:open-listener "127.0.0.1" 0)))
    (is-true srv)
    (when srv
      (unwind-protect
          (let* ((port (usocket:get-local-port srv))
                 (server-peer nil)
                 ;; The accept side runs in its own thread (accept + the inbound
                 ;; handshake), as it would under the node's listener thread.
                 (server-thread
                   (bt:make-thread
                    (lambda ()
                      ;; This loopback dial is a REAL self-connection: one
                      ;; image dials its own listener, so the client's VERSION
                      ;; carries a nonce our own outbound registry holds and
                      ;; the inbound side would (correctly) refuse it. Give
                      ;; this thread its own empty registry so it stands in for
                      ;; a genuinely distinct node — dynamic bindings are
                      ;; thread-local, so this cannot affect the dialing side.
                      ;; The refusal itself is asserted by
                      ;; inbound-handshake-refuses-self-connection below.
                      (with-private-outbound-nonces
                        (let ((conn (bl.net:accept-connection srv :timeout 10)))
                          (when conn
                            (let ((p (bl.net:make-inbound-peer conn "127.0.0.1")))
                              (when (bl.net:perform-inbound-handshake p)
                                (setf server-peer p)))))))
                    :name "test-inbound-accept")))
            ;; Give the accept thread a moment to block on accept, then dial in.
            (sleep 0.3)
            (let ((client (bl.net:connect-peer "127.0.0.1" port)))
              (is-true client)
              (when client
                (is-true (bl.net:perform-handshake client))
                (is (eq :ready (bl.net:peer-state client)))
                ;; Wait for the inbound side to finish (handshake timeouts bound this).
                (bt:join-thread server-thread)
                (is-true server-peer)
                (when server-peer
                  (is (eq :ready (bl.net:peer-state server-peer)))
                  (is-true (bl.net:peer-inbound server-peer))
                  ;; The inbound side recorded the dialer's version/user-agent.
                  (is-true (bl.net:peer-version server-peer))
                  (bl.net:disconnect-peer server-peer))
                (bl.net:disconnect-peer client))))
        (bl.net:close-listener srv)))))

(test open-listener-unbindable-returns-nil
  ;; Binding a non-local address (TEST-NET-1, never a local interface) fails
  ;; gracefully — open-listener returns NIL, not an error (the contract callers
  ;; like start-inbound-listener rely on).
  (is (null (bl.net:open-listener "192.0.2.1" 0))))

;;;; ============================================================
;;;; G7-19: self-connection detection (Core CheckIncomingNonce)
;;;; ============================================================

(test self-connection-nonce-registry
  "The registry is armed for exactly the handshake window: registered before
we send VERSION, released when the handshake ends — SUCCESS OR FAILURE. Core
matches only against !fSuccessfullyConnected nodes; a leaked entry would stay
armed forever and refuse an unrelated future peer that happened to reuse the
value."
  (with-private-outbound-nonces
    (let ((n (bl.net::%fresh-local-nonce)))
      (is-false (bl.net::self-connection-nonce-p n))
      (bl.net::%register-outbound-nonce n)
      (is-true (bl.net::self-connection-nonce-p n))
      (bl.net::%release-outbound-nonce n)
      (is-false (bl.net::self-connection-nonce-p n)
                "release must clear the entry"))))

(test self-connection-nonce-is-per-connection
  "Core gives every CNode its own nonce (net.cpp:515-516 / :1824-1825) rather
than reusing a node-wide value. A stable nonce would travel in cleartext in the
first message of every connection — a permanent unique fingerprint linking our
clearnet, Tor and I2P identities and every reconnect."
  (let ((nonces (loop repeat 50
                      collect (bl.net::%fresh-local-nonce))))
    (is (= 50 (length (remove-duplicates nonces)))
        "nonces must not repeat across connections")
    (is (every (lambda (n) (typep n '(unsigned-byte 64))) nonces))
    ;; Not all clustered in a tiny range (a broken RNG returning small ints).
    (is (> (reduce #'max nonces) (expt 2 32))
        "nonces must span the full 64-bit space")))

(defun %twice-under-one-random-state (thunk)
  "THUNK's value under the same *random-state* twice -- what two processes
running the same build produce when the value comes from CL:RANDOM."
  (list (let ((*random-state* (sb-ext:seed-random-state 90210))) (funcall thunk))
        (let ((*random-state* (sb-ext:seed-random-state 90210))) (funcall thunk))))

(test published-nonces-are-not-drawn-from-the-shared-random-state
  "GA11 4a05974e. The VERSION nonce, the ping nonce and the BIP330 salt all go
out on the wire in cleartext. %FRESH-LOCAL-NONCE already read the OS source and
is here as a regression guard; the ping nonce, MAKE-VERSION-MESSAGE-BYTES's
default (what a caller that does not pass one publishes) and the salt were
(random (expt 2 64)) off the one
process-global CL:*RANDOM-STATE*, the same MT19937 stream as addrman's
new/tried selection, the addr-relay reservoir and timers, and the feeler
cadence. MT19937 is not a CSPRNG: 624 consecutive tempered outputs recover its
19937-bit state in closed form, and it runs backwards as well as forwards -- so
a peer collecting our published nonces (one long-lived connection's pings will
do) learns which address we dial next. Core draws every one of these from a
FastRandomContext, OS-seeded ChaCha20 (random.h; PeerManagerImpl::m_rng,
net_processing.cpp).

Replaying one *random-state* is exactly two starts of one build. The nonces
must still differ; the control at the end shows the harness would catch it if
they did not. The salt itself is drawn inside %MAYBE-SEND-SENDTXRCNCL, which
needs a live connection to observe, and shares the source asserted here."
  (destructuring-bind (a b)
      (%twice-under-one-random-state #'bl.net::%fresh-local-nonce)
    (is (/= a b) "two VERSION nonces under one replayed *random-state* were both ~D" a))
  (destructuring-bind (a b)
      (%twice-under-one-random-state (lambda () (bl.ser:make-ping-message)))
    (is (not (equalp a b)) "two ping messages under one replayed *random-state* were identical"))
  (destructuring-bind (a b)
      ;; Everything but the nonce pinned, so only the nonce can differ.
      (%twice-under-one-random-state
       (lambda () (bl.ser:make-version-message-bytes :timestamp 1757000000)))
    (is (not (equalp a b)) "two VERSION messages under one replayed *random-state* were identical"))
  ;; Positive control: the draw these replaced does repeat, so the assertions
  ;; above are testing the source and not the re-seeding.
  (destructuring-bind (a b)
      (%twice-under-one-random-state (lambda () (random (expt 2 64))))
    (is (= a b) "positive control: CL:RANDOM was expected to replay a re-seeded state")))

(test outbound-handshake-sends-its-own-nonce
  "The VERSION we push must carry THIS connection's nonce, not a fresh
throwaway — otherwise the registry holds a value that never goes on the wire
and self-connection is undetectable while every test still passes."
  (let* ((peer (bl.net:make-peer))
         (nonce (bl.net::%fresh-local-nonce)))
    (setf (bl.net::peer-local-nonce peer) nonce)
    (let* ((payload (bl.ser:make-version-message-bytes
                     :nonce (bl.net::peer-local-nonce peer)))
           (parsed (bl.bytes:with-byte-reader (s payload)
                     (bl.ser:read-version-message s))))
      (is (= nonce (bl.ser:version-message-nonce parsed))
          "the nonce on the wire must be the peer's own"))))

(test inbound-handshake-stores-a-sanitized-user-agent
  "GA11 1052063f. The subversion a peer sends is stored on the peer, written to
debug.log at handshake and returned as getpeerinfo's \"subver\". Core stores
SanitizeString(strSubVer) as cleanSubVer (net_processing.cpp:3641) and keeps
the raw string nowhere, so the newline that would forge a debug.log line is
gone before any of those readers see it -- %log-escape-message passes a newline
through, deliberately and exactly as Core's LogEscapeMessage does, because the
boundary filter has already run.

Drives a real handshake over loopback so the assertion covers the STORE, not
the sanitizer: the client advertises a poisoned user agent and the server side
must hold the filtered one."
  (let ((srv (bl.net:open-listener "127.0.0.1" 0))
        (poisoned (concatenate 'string
                               "/poison:1.0/" (string #\Newline)
                               "FORGED Shutdown: done"
                               (string (code-char 27)) "[31m")))
    (is-true srv)
    (when srv
      (unwind-protect
           (let* ((port (usocket:get-local-port srv))
                  (stored :never-ran)
                  (server-thread
                    (bt:make-thread
                     (lambda ()
                       ;; A registry of its own: this stands in for a distinct
                       ;; node, so our own nonce must not look like a
                       ;; self-connection.
                       (with-private-outbound-nonces
                         (let ((conn (bl.net:accept-connection srv :timeout 10)))
                           (when conn
                             (let ((p (bl.net:make-inbound-peer conn "127.0.0.1")))
                               (bl.net:perform-inbound-handshake p)
                               (setf stored (bl.net:peer-user-agent p))
                               (ignore-errors (bl.net:disconnect-peer p)))))))
                     :name "test-subver-accept")))
             (sleep 0.3)
             (let ((client (let ((bl.ser:*user-agent* poisoned))
                             (bl.net:connect-peer "127.0.0.1" port))))
               (is-true client)
               (when client
                 (let ((bl.ser:*user-agent* poisoned))
                   (ignore-errors (bl.net:perform-handshake client)))
                 (bt:join-thread server-thread)
                 (is-true (stringp stored)
                          "the inbound side never stored a user agent (~S)" stored)
                 (when (stringp stored)
                   (is (null (find #\Newline stored))
                       "a newline reached the stored subversion: ~S" stored)
                   (is (null (find (code-char 27) stored))
                       "an ESC reached the stored subversion: ~S" stored)
                   (is (string= (bl.bytes:sanitize-string poisoned) stored)
                       "the stored subversion is not the sanitized one: ~S" stored)
                   ;; Positive control: the poisoned agent DID have something to
                   ;; drop, so a stored raw string would have been caught.
                   (is (< (length stored) (length poisoned))
                       "positive control: nothing was dropped from ~S" poisoned))
                 (ignore-errors (bl.net:disconnect-peer client)))))
        (bl.net:close-listener srv)))))

(test inbound-handshake-refuses-self-connection
  "THE BUG (G7-19): dialing our own advertised address completed the handshake
against ourselves. That connection answers ping/pong forever, is never evicted,
permanently burns an outbound slot and pollutes addrman and getpeerinfo.

Here the inbound side keeps the SHARED registry, so the loopback dial is seen
for what it is — a self-connection — and refused. Contrast
inbound-handshake-loopback, which rebinds the registry in the server thread to
stand in for a distinct node."
  (let ((srv (bl.net:open-listener "127.0.0.1" 0)))
    (is-true srv)
    (when srv
      (unwind-protect
           (let* ((port (usocket:get-local-port srv))
                  (accepted nil)
                  (server-thread
                    (bt:make-thread
                     (lambda ()
                       (let ((conn (bl.net:accept-connection srv :timeout 10)))
                         (when conn
                           (let ((p (bl.net:make-inbound-peer conn "127.0.0.1")))
                             ;; Shared registry on purpose: this IS us.
                             (setf accepted
                                   (bl.net:perform-inbound-handshake p))
                             (ignore-errors
                              (bl.net:disconnect-peer p))))))
                     :name "test-selfconn-accept")))
             (sleep 0.3)
             (let ((client (bl.net:connect-peer "127.0.0.1" port)))
               (is-true client)
               (when client
                 ;; The dial itself may fail once the far side hangs up; what
                 ;; matters is that the inbound side refused the handshake.
                 (ignore-errors (bl.net:perform-handshake client))
                 (bt:join-thread server-thread)
                 (is (null accepted)
                     "the inbound side must refuse a connection carrying our own nonce")
                 ;; Always close the client socket, or the suite can hang on a
                 ;; lingering connection.
                 (ignore-errors (bl.net:disconnect-peer client)))))
        (bl.net:close-listener srv)))))

(test the-accept-loop-does-not-wait-for-a-silent-peer
  "Core adds an accepted socket to m_nodes AT ONCE (net.cpp:1854-1858) and lets
ThreadMessageHandler run the version exchange, so its accept loop never waits
on a peer. Ours ran PERFORM-INBOUND-HANDSHAKE inline on the listener thread,
which serialised every inbound connection behind the slowest handshake: with
p2p_leak.py's first peer -- a LazyPeer that sends nothing at all -- the node's
own log shows the second connection accepted 15 s after it and the third 30 s
after it, and by then the first had been dropped, which is exactly what
p2p_leak.py:131 asserts against. p2p_eviction.py:90, p2p_getaddr_caching.py:74
and p2p_ibd_stalling.py connect peers in bulk and pay the same toll each.

A client dials and then says nothing; a second client dials while the first is
still being waited on and must complete its whole handshake. The second client
runs with its own outbound-nonce registry so the inbound side does not
(correctly) refuse a loopback dial as a self-connection."
  (let ((srv (bl.net:open-listener "127.0.0.1" 0)))
    (is-true srv)
    (when srv
      (let* ((node (bl:make-node))
             (port (usocket:get-local-port srv))
             (silent nil)
             (listener nil)
             (client-thread nil)
             (good nil))
        (setf (bl:node-running node) t)
        (unwind-protect
             (progn
               (setf listener
                     (bt:make-thread (lambda () (bl:run-inbound-listener node :socket srv))
                                     :name "test-inbound-listener"))
               (sleep 0.3)
               ;; p2p_leak.py's LazyPeer: connect, send nothing, ever.
               (setf silent (usocket:socket-connect
                             "127.0.0.1" port
                             :element-type '(unsigned-byte 8)))
               (sleep 0.5)
               (setf client-thread
                     (bt:make-thread
                      (lambda ()
                        ;; An unhandled condition in a test thread drops a
                        ;; non-interactive image into the debugger, which
                        ;; reads as a hung suite.
                        (ignore-errors
                         (with-private-outbound-nonces
                           (let ((c (bl.net:connect-peer "127.0.0.1" port)))
                             (when (and c (bl.net:perform-handshake c))
                               (setf good c))))))
                      :name "test-inbound-client"))
               ;; TIMING-SENSITIVE, with a wide margin on purpose: the whole
               ;; question is latency, and the two answers are ~0.05 s (the
               ;; handshake runs on its own thread) against 15 s (the accept
               ;; loop waits out PERFORM-INBOUND-HANDSHAKE's timeout on the
               ;; silent peer first, measured in this image). Five seconds sits
               ;; two orders of magnitude from one and three times clear of the
               ;; other.
               (let ((deadline (+ (get-internal-real-time)
                                  (* 5 internal-time-units-per-second))))
                 ;; Wait for the SERVER side to finish: the queue holds the
                 ;; silent peer from the moment it is accepted, so its presence
                 ;; proves nothing -- a :READY peer in it does.
                 (loop until (or (and good
                                      (find :ready (bl:node-pending-inbound-peers node)
                                            :key #'bl.net:peer-state))
                                 (> (get-internal-real-time) deadline))
                       do (sleep 0.02)))
               ;; The behavioural assertions, in pre-existing names only.
               (is-true good
                        "a second peer handshakes within five seconds while the first stays silent")
               (when good
                 (is (eq :ready (bl.net:peer-state good))))
               ;; BOTH accepted connections are queued, because a peer is
               ;; published at ACCEPT now (Core's CNode joins m_nodes there,
               ;; net.cpp:1854-1858, and rpc_net.py:137 reads a getpeerinfo row
               ;; for a peer that never sent a version). What separates them is
               ;; the STATE: only the one that handshaked is :READY, and only a
               ;; :READY peer is touched by any sync-thread socket duty.
               (let ((queued (bl:node-pending-inbound-peers node)))
                 (is (= 2 (length queued))
                     "both accepted connections are queued, silent one included")
                 (is (= 1 (count :ready queued :key #'bl.net:peer-state))
                     "and exactly one of them has finished its handshake")
                 (is (= 1 (count-if #'bl.net:peer-handshake-in-flight-p queued))
                     "the silent peer is still mid-handshake"))
               ;; The silent peer is still being waited on, on its own thread.
               (is (plusp (bl:inbound-handshakes-in-flight))
                   "the silent peer's handshake is still in flight"))
          (setf (bl:node-running node) nil)
          (when client-thread (ignore-errors (bt:join-thread client-thread)))
          (when good (ignore-errors (bl.net:disconnect-peer good)))
          (when silent (ignore-errors (usocket:socket-close silent)))
          (when listener (ignore-errors (bt:join-thread listener)))
          (dolist (p (bl:node-pending-inbound-peers node))
            (ignore-errors (bl.net:disconnect-peer p)))
          (bl.net:close-listener srv))))))

(test the-post-version-capabilities-follow-the-negotiated-version
  "Core gates the two post-VERSION capability messages on
greatest_common_version = min(their nVersion, PROTOCOL_VERSION)
(net_processing.cpp:3668): wtxidrelay at WTXID_RELAY_VERSION (70016,
:3715-3717) and sendaddrv2 at 70016 too, which Core's own comment calls a
courtesy -- \"some implementations reject messages they don't know\"
(:3719-3726).

Ours sent sendaddrv2 to every peer whatever it announced, and gated
wtxidrelay on whether OUR side relays transactions, which is not one of
Core's conditions. p2p_leak.py:123 connects a peer announcing protocol 70015
and asserts at :154-155 that it received neither message; both arrived.

Driven over a real loopback pair: the client sends a raw VERSION of the given
protocol and collects every command the node sends back."
  (flet ((commands-for (their-version)
           (let ((srv (bl.net:open-listener "127.0.0.1" 0)))
             (is-true srv)
             (when srv
               (unwind-protect
                    (let* ((port (usocket:get-local-port srv))
                           (server
                             (bt:make-thread
                              (lambda ()
                                (ignore-errors
                                 (let ((conn (bl.net:accept-connection srv :timeout 10)))
                                   (when conn
                                     (let ((p (bl.net:make-inbound-peer conn "127.0.0.1")))
                                       (bl.net:perform-inbound-handshake p)
                                       (sleep 0.4)
                                       (ignore-errors (bl.net:disconnect-peer p)))))))
                              :name "test-caps-server")))
                      (sleep 0.2)
                      (let ((client (bl.net:connect-peer "127.0.0.1" port))
                            (commands '()))
                        (unwind-protect
                             (when client
                               (bl.net:send-bytes
                                (bl.net:peer-connection client)
                                (bl.ser:serialize-message
                                 "version"
                                 (bl.ser:make-version-message-bytes
                                  :version their-version)))
                               (bl.net:send-bytes
                                (bl.net:peer-connection client)
                                (bl.ser:make-verack-message))
                               (loop repeat 60
                                     do (let ((c (bl.net:receive-message client)))
                                          (if c (push c commands) (sleep 0.02)))))
                          (when client (ignore-errors (bl.net:disconnect-peer client)))
                          (ignore-errors (bt:join-thread server)))
                        (nreverse commands)))
                 (bl.net:close-listener srv))))))
    (let ((modern (commands-for 70016))
          (old (commands-for 70015)))
      (flet ((sent (commands name) (and (member name commands :test #'string=) t)))
        ;; Control first: the node answered both clients at all.
        (is-true (sent modern "version") "control: the node answered the modern client")
        (is-true (sent old "version") "control: the node answered the old client")
        (is-true (sent modern "wtxidrelay")
                 "a 70016 peer is offered wtxid relay")
        (is-true (sent modern "sendaddrv2")
                 "and addrv2")
        (is-false (sent old "wtxidrelay")
                  "a 70015 peer must not be offered wtxid relay")
        (is-false (sent old "sendaddrv2")
                  "nor addrv2, which Core withholds as a courtesy below 70016")))))
