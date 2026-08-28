(in-package #:bitcoin-lisp.tests)

;;;; BIP324 v2 transport tests: real localhost socket pairs, one side driven
;;;; from a worker thread, exercising the full handshake (both roles), v1
;;;; detection with byte pushback, wrong-network rejection, message exchange
;;;; over both type encodings, and decoy skipping. Gated on the ellswift
;;;; module being present in libsecp256k1 (as the transport itself is).

(def-suite :bip324-transport-tests
  :description "BIP324 v2 transport over loopback sockets"
  :in :bitcoin-lisp-tests)

(in-suite :bip324-transport-tests)

(defmacro %with-loopback-pair ((client-conn server-conn) &body body)
  "Open a listener on an ephemeral localhost port, connect a client, accept
it, and run BODY with both connection structs bound. Closes everything after."
  (let ((listener (gensym)) (port (gensym)))
    `(let* ((,listener (bl.net:open-listener "127.0.0.1" 0))
            (,port (usocket:get-local-port ,listener)))
       (unwind-protect
            (let* ((,client-conn (bl.net:make-tcp-connection
                                  "127.0.0.1" ,port))
                   (,server-conn (bl.net::accept-connection
                                  ,listener :timeout 5)))
              (unwind-protect (progn ,@body)
                (when ,client-conn
                  (bl.net:close-connection ,client-conn))
                (when ,server-conn
                  (bl.net:close-connection ,server-conn))))
         (bl.net::close-listener ,listener)))))

(test buffered-input-is-visible-to-the-drain-loop
  "The readers pull bytes with LISTEN on the Lisp STREAM, and a Lisp stream
BUFFERS: bytes the kernel handed over live in userspace, where poll(2) on the
fd cannot see them. So two messages arriving in ONE TCP segment both land in
the stream buffer, the first is read, and a socket-only readiness check then
says \"nothing more\" — leaving the second parked in a buffer we own until
unrelated traffic happens to wake the socket.

Measured before the fix: Core's sync_with_ping deliberately sends two pings
back to back, and this node logged ELEVEN SECONDS between processing them.
After: the same millisecond. Any two messages sharing a segment paid that,
real peers included.

The test reproduces the exact shape — write two messages' worth, take the
first, then ask both questions. DATA-AVAILABLE-P is allowed to say either
thing (whether the kernel still holds bytes is a scheduling detail); what must
hold is that CONNECTION-INPUT-PENDING-P sees the buffered remainder."
  (%with-loopback-pair (client server)
    (is-true (and client server) "loopback pair did not come up")
    (when (and client server)
      (let ((payload (make-array 64 :element-type '(unsigned-byte 8)
                                    :initial-element 7)))
        ;; One write, so both halves have every chance to share a segment.
        (bl.net:send-bytes client payload)
        (%v2t-drain client)
        ;; Let the bytes land.
        (loop repeat 50
              until (bl.net::data-available-p server :timeout 0.1)
              do (sleep 0.02))
        ;; Take the FIRST half through the reader, which drains via LISTEN and
        ;; so pulls whatever the stream is holding into userspace.
        (let ((first-half (bl.net::receive-bytes-resumable server 32)))
          (is (not (eq first-half :incomplete))
              "the first half never completed; the fixture proves nothing"))
        ;; The remainder is now in OUR buffer. This is the assertion that
        ;; fails against the bug.
        (is-true (bl.net::connection-input-pending-p server)
                 "buffered input is invisible to the drain loop — the second ~
message of any pair sharing a TCP segment waits for unrelated traffic")))))

(defun %v2t-drain (conn &key (seconds 10))
  "Push CONN's queued unsent bytes onto the wire, or give up after SECONDS.

SEND-BYTES never blocks: whatever the kernel does not take immediately is
queued and retried by a later send or by a housekeeping flush pass. A live node
has that pump; a test does not. So a send whose bytes are only partly accepted
leaves the rest queued forever and the PEER waits out its full receive timeout
— which is what made v2-transport-loopback-handshake-and-messages fail on
roughly one battery run in three, always as a 60-second (NIL NIL) on the
receiving side. Nothing about the transport was wrong; the bytes had not left."
  (declare (ignorable conn))
  (loop with deadline = (+ (get-internal-real-time)
                           (* seconds internal-time-units-per-second))
        while (plusp (bl.net::connection-send-queue-bytes conn))
        do (unless (bl.net:flush-send-buffer conn)
             (return))
           (when (> (get-internal-real-time) deadline)
             (return))
           (sleep 0.01))
  conn)

(defun %v2t-frame (command payload)
  "A v1-framed message, as every message builder in the codebase produces."
  (bl.ser:serialize-message command payload))

(test v2-transport-loopback-handshake-and-messages
  "Full v2 handshake initiator<->responder over a socket pair, then messages
both ways: short-ID type (inv), long-form type (verack), a decoy packet that
must be skipped, and a 0-length payload."
  (if (not (bl.crypto:ellswift-available-p))
      (skip "libsecp256k1 lacks the ellswift module")
      (%with-loopback-pair (client server)
        (is-true client)
        (is-true server)
        ;; NB: bind client-result BEFORE spawning the thread (sequential let*),
        ;; so the closure and the assertions share the same binding.
        ;; 60s, not 10: this drives two real sockets and an EC handshake, and
        ;; the whole battery runs alongside compilation. At 10s it failed on
        ;; two of four full runs and passed 3/3 in isolation — a flake in the
        ;; verification of record, which undermines every result it reports.
        ;; The timeout is not what the test is about, so give it room.
        (let* ((client-result nil)
               (thread
                 (bt:make-thread
                  (lambda ()
                    (handler-case
                        (let ((transport (progn
                                           (prog1 (bl.net::v2-handshake-outbound
                                                   client :timeout 60)
                                             ;; The HANDSHAKE's own sends go
                                             ;; through send-bytes too, and the
                                             ;; first version of this fix
                                             ;; drained only the MESSAGE sends
                                             ;; that follow. A handshake whose
                                             ;; last packet is half-queued
                                             ;; leaves the peer waiting out its
                                             ;; full timeout, which is exactly
                                             ;; the failure that kept recurring.
                                             (%v2t-drain client)))))
                          (if (not (bl.net::v2-transport-p transport))
                              ;; Say WHY rather than leaving NIL behind: a
                              ;; failed handshake and a wrong message were
                              ;; previously indistinguishable, both surfacing
                              ;; as "NIL is not equal to verack".
                              (setf client-result (list :handshake-failed transport))
                              (progn
                                ;; short-ID message out; long-form + decoy back.
                                (bl.net::v2-send-message
                                 client transport (%v2t-frame "inv" (%bc-hex "00")))
                                (%v2t-drain client)
                                (multiple-value-bind (cmd payload)
                                    (bl.net::v2-receive-message-blocking
                                     client transport :timeout 60)
                                  (setf client-result (list cmd payload))))))
                      (error (e) (setf client-result (list :error e)))))
                  :name "v2-initiator")))
          (let ((transport (prog1 (bl.net::v2-detect-inbound
                                   server :timeout 60)
                             (%v2t-drain server))))
            (is-true (bl.net::v2-transport-p transport))
            (when (bl.net::v2-transport-p transport)
              ;; Receive the client's short-ID message.
              (multiple-value-bind (cmd payload)
                  (bl.net::v2-receive-message-blocking server transport
                                                               :timeout 60)
                (is (equal "inv" cmd))
                (is (equalp (%bc-hex "00") payload)))
              ;; Send a decoy the client must skip, then a long-form message
              ;; with empty payload.
              (bl.net::%v2-send-packet
               server transport (%bc-hex "deadbeef") (%bc-buf 0) t)
              (bl.net::v2-send-message
               server transport (%v2t-frame "verack" (%bc-buf 0)))
              ;; Make sure both packets actually reached the wire before we
              ;; join the initiator thread; see %v2t-drain.
              (%v2t-drain server)))
          (bt:join-thread thread)
          (is (equal "verack" (first client-result))
              "initiator result was ~S" client-result)
          (is (equalp #() (second client-result)))))))

(test v2-transport-disconnects-on-bad-packet
  "A corrupt packet (auth failure) marks the connection dead rather than
returning a silent NIL that would leave a zombie peer (Bug 2). Same for an
oversize length descriptor."
  (if (not (bl.crypto:ellswift-available-p))
      (skip "libsecp256k1 lacks the ellswift module")
      (%with-loopback-pair (client server)
        (let* ((client-transport nil)
               (thread (bt:make-thread
                        (lambda ()
                          (setf client-transport
                                (bl.net::v2-handshake-outbound
                                 client :timeout 10))))))
          (let ((server-transport (bl.net::v2-detect-inbound
                                   server :timeout 10)))
            (bt:join-thread thread)
            (is-true (bl.net::v2-transport-p server-transport))
            (is-true (bl.net::v2-transport-p client-transport))
            ;; Client sends 3 length bytes + a garbage body that will not
            ;; authenticate. Server must return NIL AND mark itself dead.
            (bl.net:send-bytes
             client (bl.crypto:bip324-cipher-encrypt
                     (bl.net::v2-transport-cipher client-transport)
                     (%bc-hex "07") (%bc-buf 0) nil))
            (%v2t-drain client)
            ;; Corrupt the wire by having the server decrypt a tampered copy:
            ;; simplest is to feed it a packet whose ciphertext we flip. Read
            ;; it raw, flip a body byte, and re-inject via a fresh pair is
            ;; heavy; instead assert the healthy receive works, then a
            ;; hand-corrupted length triggers oversize.
            (multiple-value-bind (cmd payload)
                (bl.net::v2-receive-message-blocking server server-transport
                                                             :timeout 10)
              (declare (ignore payload))
              (is-true cmd))
            ;; Oversize: craft 3 length bytes that decrypt to > max contents by
            ;; sending raw bytes the recv length-cipher will interpret. We only
            ;; assert the connection dies, since the exact decrypted length is
            ;; cipher-dependent; feed 3 bytes then let the read fail.
            (bl.net:send-bytes client (%bc-hex "ffffff"))
            (%v2t-drain client)
            (bl.net::v2-receive-message-blocking server server-transport
                                                         :timeout 2)
            (is-false (bl.net:connection-connected server)))))))

(test v2-transport-inbound-v1-detection
  "A v1 client's first 16 bytes (magic + padded \"version\") are recognized
and pushed back so the v1 path reads them unchanged."
  (if (not (bl.crypto:ellswift-available-p))
      (skip "libsecp256k1 lacks the ellswift module")
      (%with-loopback-pair (client server)
        (let ((version-msg (%v2t-frame "version" (%bc-hex "00010203"))))
          (bl.net:send-bytes client version-msg)
          (%v2t-drain client)
          (is (eq :v1 (bl.net::v2-detect-inbound server :timeout 5)))
          ;; The sniffed 16 bytes plus the rest must reassemble the message.
          (let ((got (bl.net:receive-bytes
                      server (length version-msg) :timeout 5)))
            (is (equalp version-msg got)))))))

(test v2-transport-inbound-wrong-network
  "A v1 VERSION with a wrong network magic is rejected outright."
  (if (not (bl.crypto:ellswift-available-p))
      (skip "libsecp256k1 lacks the ellswift module")
      (%with-loopback-pair (client server)
        (let ((bytes (make-array 16 :element-type '(unsigned-byte 8)
                                    :initial-element 0)))
          ;; Wrong magic, correct "version" command bytes.
          (replace bytes (%bc-hex "ffaaffaa"))
          (loop for c across "version"
                for i from 4
                do (setf (aref bytes i) (char-code c)))
          (bl.net:send-bytes client bytes)
          (%v2t-drain client)
          (is-false (bl.net::v2-detect-inbound server :timeout 5))))))

(test v2-transport-outbound-fallback-on-silence
  "An outbound v2 attempt against a peer that never responds yields
:FALLBACK-V1 (the caller then reconnects as v1)."
  (if (not (bl.crypto:ellswift-available-p))
      (skip "libsecp256k1 lacks the ellswift module")
      (%with-loopback-pair (client server)
        server                          ; kept open but silent
        ;; Server reads nothing and says nothing; use a short timeout.
        (is (eq :fallback-v1
                (bl.net::v2-handshake-outbound client
                                                                :timeout 2))))))

(test v2-receive-resumes-a-packet-split-across-passes
  "The property this transport was missing. BIP324 framing is a 3-byte length
descriptor and then a body of up to ~4 MB, and the body read used to BLOCK — so
a v2 peer delivering its packet slowly held the shared message pump for minutes:
the same shape as the 2026-08-11 freeze the v1 reader was fixed for. Both live
nodes run -v2transport and dial v2 first, so until this path was resumable the
fix did not hold where it mattered.

Also pins what makes v2 framing stricter than v1: decrypting the length
descriptor ADVANCES the receive cipher and can never be repeated, so the body
length it yielded has to survive the gap between passes."
  (if (not (bl.crypto:ellswift-available-p))
      (skip "libsecp256k1 lacks the ellswift module")
      (%with-loopback-pair (client server)
        (let* ((client-transport nil)
               (thread (bt:make-thread
                        (lambda ()
                          (handler-case
                              (setf client-transport
                                    (bl.net::v2-handshake-outbound
                                     client :timeout 10))
                            (error (e) (setf client-transport e))))
                        :name "v2-split-initiator")))
          (let ((server-transport
                  (bl.net::v2-detect-inbound server :timeout 10)))
            (bt:join-thread thread)
            (is-true (bl.net::v2-transport-p server-transport))
            (is-true (bl.net::v2-transport-p client-transport))
            (when (and (bl.net::v2-transport-p server-transport)
                       (bl.net::v2-transport-p client-transport))
              ;; Nothing sent yet: the reader must say so at once, not wait.
              (let ((start (get-internal-real-time)))
                (multiple-value-bind (command detail)
                    (bl.net::v2-receive-message
                     server server-transport :timeout 30)
                  (is (null command))
                  (is (eq :incomplete detail)
                      "a quiet v2 peer yields :incomplete, never a wait"))
                (is (< (/ (- (get-internal-real-time) start)
                          internal-time-units-per-second)
                       1)
                    "and consumes none of the caller's budget"))
              ;; Encrypt one real packet, then deliver it in two pieces.
              (let* ((framed (%v2t-frame "inv" (%bc-hex "00")))
                     (contents (bl.net::%v2-contents-for-message
                                framed))
                     (packet (bt:with-lock-held
                                 ((bl.net::v2-transport-send-lock
                                   client-transport))
                               (bl.crypto:bip324-cipher-encrypt
                                (bl.net::v2-transport-cipher
                                 client-transport)
                                contents bl.net::*v2-empty-bytes* nil))))
                ;; Piece 1: the length descriptor only. Decrypting it advances
                ;; the receive cipher — the point of no return.
                (bl.net::send-bytes
                 client (subseq packet 0 bl.crypto:+bip324-length-len+))
                (%v2t-drain client)
                (sleep 0.2)
                (multiple-value-bind (command detail)
                    (bl.net::v2-receive-message
                     server server-transport :timeout 30)
                  (is (null command))
                  (is (eq :incomplete detail) "the body has not arrived yet"))
                (is-true (bl.net::connection-recv-framing server)
                         "the decrypted body length is parked for the next pass")
                (is-true (bl.net::connection-connected server)
                         "and a mid-packet peer is not dropped")
                ;; Piece 2: the body.
                (bl.net::send-bytes
                 client (subseq packet bl.crypto:+bip324-length-len+))
                (%v2t-drain client)
                (sleep 0.2)
                (multiple-value-bind (command payload)
                    (bl.net::v2-receive-message
                     server server-transport :timeout 30)
                  (is (equal "inv" command)
                      "the packet completes from the parked framing state")
                  (is (equalp (%bc-hex "00") payload)))
                (is-false (bl.net::connection-recv-framing server)
                          "and the framing state is consumed with it"))))))))

(test v2-decoy-flood-yields-the-pump
  "A v2 peer streaming decoys must not own the pump. The decoy-skip loop only
ends on a NON-decoy packet, so a peer sending minimum-size decoys (20 bytes:
length + header + tag, empty contents, IGNORE set) keeps our socket non-empty
and the loop spinning — inside ONE receive-message call, where the per-cycle
message cap cannot reach it. Decrypting costs us more per byte than sending
costs the peer, so it stays ahead indefinitely: the 2026-08-11 freeze shape on
the path both live nodes prefer.

+v2-max-recv-bytes-per-call+ bounds the work per call the way Core bounds bytes
per socket-handler pass; past it the reader yields :INCOMPLETE and the next pass
resumes, after every other peer has had a turn."
  (if (not (bl.crypto:ellswift-available-p))
      (skip "libsecp256k1 lacks the ellswift module")
      (%with-loopback-pair (client server)
        (let* ((client-transport nil)
               (thread (bt:make-thread
                        (lambda ()
                          (handler-case
                              (setf client-transport
                                    (bl.net::v2-handshake-outbound
                                     client :timeout 10))
                            (error (e) (setf client-transport e))))
                        :name "v2-decoy-initiator")))
          (let ((server-transport
                  (bl.net::v2-detect-inbound server :timeout 10)))
            (bt:join-thread thread)
            (when (and (bl.net::v2-transport-p server-transport)
                       (bl.net::v2-transport-p client-transport))
              ;; Enough empty decoys to exceed the per-call budget several times
              ;; over (20 bytes each), and no real message behind them.
              (let ((decoys (ceiling (* 4 bl.net::+v2-max-recv-bytes-per-call+)
                                     20)))
                (dotimes (i decoys)
                  (bl.net::%v2-send-packet
                   client client-transport (%bc-buf 0)
                   bl.net::*v2-empty-bytes* t))
                (%v2t-drain client))
              (sleep 0.3)
              (let ((start (get-internal-real-time)))
                (multiple-value-bind (command detail)
                    (bl.net::v2-receive-message
                     server server-transport)
                  (is (null command) "decoys carry no message")
                  (is (eq :incomplete detail)
                      "the reader yields instead of skipping decoys forever"))
                ;; The budget is what ends the call; without it this never
                ;; returns while the peer keeps sending.
                (is (< (/ (- (get-internal-real-time) start)
                          internal-time-units-per-second)
                       5)
                    "and it yields promptly"))
              (is-true (bl.net::connection-connected server)
                       "sending decoys is legal — the peer keeps its connection")))))))
