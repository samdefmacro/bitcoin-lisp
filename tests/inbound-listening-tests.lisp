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
                      (let ((conn (bitcoin-lisp.networking:accept-connection srv :timeout 10)))
                        (when conn
                          (let ((p (bitcoin-lisp.networking:make-inbound-peer conn "127.0.0.1")))
                            (when (bitcoin-lisp.networking:perform-inbound-handshake p)
                              (setf server-peer p))))))
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
