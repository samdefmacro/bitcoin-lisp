(in-package #:bitcoin-lisp.tests)

;;; Inbound listening tests.
;;;
;;; End-to-end over loopback: open a listener, dial it from a client, and assert
;;; both sides complete the version handshake — the inbound side via
;;; perform-inbound-handshake (receive version first), the outbound side via the
;;; existing perform-handshake. Both peers must reach :ready, and the accepted
;;; peer must be flagged inbound.

(in-suite :inbound-listening-tests)

(test inbound-handshake-loopback
  (let ((srv (bitcoin-lisp.networking:open-listener "127.0.0.1" 0)))
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
                      (let ((bitcoin-lisp.networking::*outbound-nonces*
                              (make-hash-table :test 'eql)))
                        (let ((conn (bitcoin-lisp.networking:accept-connection srv :timeout 10)))
                          (when conn
                            (let ((p (bitcoin-lisp.networking:make-inbound-peer conn "127.0.0.1")))
                              (when (bitcoin-lisp.networking:perform-inbound-handshake p)
                                (setf server-peer p)))))))
                    :name "test-inbound-accept")))
            ;; Give the accept thread a moment to block on accept, then dial in.
            (sleep 0.3)
            (let ((client (bitcoin-lisp.networking:connect-peer "127.0.0.1" port)))
              (is-true client)
              (when client
                (is-true (bitcoin-lisp.networking:perform-handshake client))
                (is (eq :ready (bitcoin-lisp.networking:peer-state client)))
                ;; Wait for the inbound side to finish (handshake timeouts bound this).
                (bt:join-thread server-thread)
                (is-true server-peer)
                (when server-peer
                  (is (eq :ready (bitcoin-lisp.networking:peer-state server-peer)))
                  (is-true (bitcoin-lisp.networking:peer-inbound server-peer))
                  ;; The inbound side recorded the dialer's version/user-agent.
                  (is-true (bitcoin-lisp.networking:peer-version server-peer))
                  (bitcoin-lisp.networking:disconnect-peer server-peer))
                (bitcoin-lisp.networking:disconnect-peer client))))
        (bitcoin-lisp.networking:close-listener srv)))))

(test open-listener-unbindable-returns-nil
  ;; Binding a non-local address (TEST-NET-1, never a local interface) fails
  ;; gracefully — open-listener returns NIL, not an error (the contract callers
  ;; like start-inbound-listener rely on).
  (is (null (bitcoin-lisp.networking:open-listener "192.0.2.1" 0))))

;;;; ============================================================
;;;; G7-19: self-connection detection (Core CheckIncomingNonce)
;;;; ============================================================

(test self-connection-nonce-registry
  "The registry is armed for exactly the handshake window: registered before
we send VERSION, released when the handshake ends — SUCCESS OR FAILURE. Core
matches only against !fSuccessfullyConnected nodes; a leaked entry would stay
armed forever and refuse an unrelated future peer that happened to reuse the
value."
  (let ((bitcoin-lisp.networking::*outbound-nonces* (make-hash-table :test 'eql)))
    (let ((n (bitcoin-lisp.networking::%fresh-local-nonce)))
      (is-false (bitcoin-lisp.networking::self-connection-nonce-p n))
      (bitcoin-lisp.networking::%register-outbound-nonce n)
      (is-true (bitcoin-lisp.networking::self-connection-nonce-p n))
      (bitcoin-lisp.networking::%release-outbound-nonce n)
      (is-false (bitcoin-lisp.networking::self-connection-nonce-p n)
                "release must clear the entry"))))

(test self-connection-nonce-is-per-connection
  "Core gives every CNode its own nonce (net.cpp:515-516 / :1824-1825) rather
than reusing a node-wide value. A stable nonce would travel in cleartext in the
first message of every connection — a permanent unique fingerprint linking our
clearnet, Tor and I2P identities and every reconnect."
  (let ((nonces (loop repeat 50
                      collect (bitcoin-lisp.networking::%fresh-local-nonce))))
    (is (= 50 (length (remove-duplicates nonces)))
        "nonces must not repeat across connections")
    (is (every (lambda (n) (typep n '(unsigned-byte 64))) nonces))
    ;; Not all clustered in a tiny range (a broken RNG returning small ints).
    (is (> (reduce #'max nonces) (expt 2 32))
        "nonces must span the full 64-bit space")))

(test outbound-handshake-sends-its-own-nonce
  "The VERSION we push must carry THIS connection's nonce, not a fresh
throwaway — otherwise the registry holds a value that never goes on the wire
and self-connection is undetectable while every test still passes."
  (let* ((peer (bitcoin-lisp.networking::make-peer))
         (nonce (bitcoin-lisp.networking::%fresh-local-nonce)))
    (setf (bitcoin-lisp.networking::peer-local-nonce peer) nonce)
    (let* ((payload (bitcoin-lisp.serialization:make-version-message-bytes
                     :nonce (bitcoin-lisp.networking::peer-local-nonce peer)))
           (parsed (flexi-streams:with-input-from-sequence (s payload)
                     (bitcoin-lisp.serialization:read-version-message s))))
      (is (= nonce (bitcoin-lisp.serialization::version-message-nonce parsed))
          "the nonce on the wire must be the peer's own"))))

(test inbound-handshake-refuses-self-connection
  "THE BUG (G7-19): dialing our own advertised address completed the handshake
against ourselves. That connection answers ping/pong forever, is never evicted,
permanently burns an outbound slot and pollutes addrman and getpeerinfo.

Here the inbound side keeps the SHARED registry, so the loopback dial is seen
for what it is — a self-connection — and refused. Contrast
inbound-handshake-loopback, which rebinds the registry in the server thread to
stand in for a distinct node."
  (let ((srv (bitcoin-lisp.networking:open-listener "127.0.0.1" 0)))
    (is-true srv)
    (when srv
      (unwind-protect
           (let* ((port (usocket:get-local-port srv))
                  (accepted nil)
                  (server-thread
                    (bt:make-thread
                     (lambda ()
                       (let ((conn (bitcoin-lisp.networking:accept-connection srv :timeout 10)))
                         (when conn
                           (let ((p (bitcoin-lisp.networking:make-inbound-peer conn "127.0.0.1")))
                             ;; Shared registry on purpose: this IS us.
                             (setf accepted
                                   (bitcoin-lisp.networking:perform-inbound-handshake p))
                             (ignore-errors
                              (bitcoin-lisp.networking:disconnect-peer p))))))
                     :name "test-selfconn-accept")))
             (sleep 0.3)
             (let ((client (bitcoin-lisp.networking:connect-peer "127.0.0.1" port)))
               (is-true client)
               (when client
                 ;; The dial itself may fail once the far side hangs up; what
                 ;; matters is that the inbound side refused the handshake.
                 (ignore-errors (bitcoin-lisp.networking:perform-handshake client))
                 (bt:join-thread server-thread)
                 (is (null accepted)
                     "the inbound side must refuse a connection carrying our own nonce")
                 ;; Always close the client socket, or the suite can hang on a
                 ;; lingering connection.
                 (ignore-errors (bitcoin-lisp.networking:disconnect-peer client)))))
        (bitcoin-lisp.networking:close-listener srv)))))
