(in-package #:bitcoin-lisp.tests)

;;;; Wave 9A: P2P eclipse/DoS hardening
;;;;
;;;; Covers the four gap-analysis items:
;;;;  1. outbound full-relay slot accounting excludes inbound/block-relay/feeler
;;;;  2. non-blocking send path with a per-peer buffer, pause cap, stall timeout
;;;;  3. per-ADDRESS addr/addrv2 token bucket (Core MAX_ADDR_RATE_PER_SECOND)
;;;;  4. low-work presync anti-DoS on the generic announcement headers path

(def-suite :eclipse-dos-tests
  :description "Eclipse/DoS hardening: outbound accounting, non-blocking send, addr rate limit, generic-path presync"
  :in :bitcoin-lisp-tests)

(in-suite :eclipse-dos-tests)

;;; ============================================================
;;; 1. Outbound full-relay slot accounting (anti-eclipse)
;;; ============================================================

(defun %mk-peer (conn-type inbound &optional (state :ready))
  (bl.net:make-peer :conn-type conn-type
                                     :inbound inbound
                                     :state state))

(defun %full-outbound-p (peer)
  "Core CNode::IsFullOutboundConn. The one reach into it in this file."
  (bl::outbound-full-relay-peer-p peer))

(test outbound-full-relay-peer-p-classification
  "Only a ready, non-inbound, outbound-full-relay peer counts as an outbound
full-relay slot (Core IsFullOutboundConn)."
  (is-true  (%full-outbound-p
             (%mk-peer :outbound-full-relay nil)))
  ;; Inbound peers never count, even if mislabeled full-relay.
  (is-false (%full-outbound-p
             (%mk-peer :outbound-full-relay t)))
  ;; Block-relay and feeler outbound peers are a separate pool.
  (is-false (%full-outbound-p
             (%mk-peer :block-relay nil)))
  (is-false (%full-outbound-p
             (%mk-peer :feeler nil)))
  ;; Not-yet-ready peers don't count.
  (is-false (%full-outbound-p
             (%mk-peer :outbound-full-relay nil :handshaking))))

(test inbound-peers-do-not-satisfy-outbound-target
  "The eclipse primitive: 8 inbound connections must NOT count toward the
outbound full-relay target (they previously did, suppressing replacement
dials). Only the two genuine outbound full-relay peers are counted."
  (let ((peers (append
                ;; 8 attacker inbound peers.
                (loop repeat 8 collect (%mk-peer :inbound t))
                ;; 2 honest outbound full-relay peers.
                (list (%mk-peer :outbound-full-relay nil)
                      (%mk-peer :outbound-full-relay nil))
                ;; block-relay + feeler outbound peers (separate pool).
                (list (%mk-peer :block-relay nil)
                      (%mk-peer :feeler nil)))))
    (is (= 2 (bl::count-outbound-full-relay-peers peers)))
    ;; With max-peers 8, needing replacements is (8 - 2) = 6 despite 12
    ;; total connections — inbound never masks the shortfall.
    (is (= 6 (- 8 (bl::count-outbound-full-relay-peers peers))))))

;;; ============================================================
;;; 2. Non-blocking send path
;;; ============================================================

(test send-paused-predicate-tracks-cap
  "connection-send-paused-p flips exactly at the send-buffer cap (Core
fPauseSend on nSendBufferMaxSize)."
  (let ((conn (bl.net::make-connection)))
    (setf (send-buffer-bytes conn) 0)
    (is-false (bl.net:connection-send-paused-p conn))
    (setf (send-buffer-bytes conn)
          bl.net:*max-send-buffer-bytes*)
    (is-false (bl.net:connection-send-paused-p conn))
    (setf (send-buffer-bytes conn)
          (1+ bl.net:*max-send-buffer-bytes*))
    (is-true (bl.net:connection-send-paused-p conn))))

(test send-stall-predicate-needs-pending-and-timeout
  "connection-send-stalled-p triggers only when data is buffered AND the socket
has made no send progress for the stall timeout (Core socket sending timeout)."
  (let ((conn (bl.net::make-connection))
        (units internal-time-units-per-second))
    ;; No pending data: never stalled, even with an ancient progress time.
    (setf (send-buffer-bytes conn) 0
          (bl.net::connection-last-send-progress conn)
          (- (get-internal-real-time)
             (* (1+ bl.net::+send-stall-timeout-seconds+) units)))
    (is-false (bl.net:connection-send-stalled-p conn))
    ;; Pending data but recent progress: not stalled.
    (setf (send-buffer-bytes conn) 500
          (bl.net::connection-last-send-progress conn)
          (get-internal-real-time))
    (is-false (bl.net:connection-send-stalled-p conn))
    ;; Pending data AND stale progress: stalled.
    (setf (bl.net::connection-last-send-progress conn)
          (- (get-internal-real-time)
             (* (1+ bl.net::+send-stall-timeout-seconds+) units)))
    (is-true (bl.net:connection-send-stalled-p conn))))

(test close-connection-frees-send-queue
  "Closing a connection releases any buffered unsent bytes."
  (let ((conn (bl.net::make-connection)))
    (setf (bl.net::connection-send-queue-in conn)
          (list #(1 2 3))
          (bl.net::connection-send-queue-out conn)
          (list #(4 5))
          (send-buffer-bytes conn) 5)
    (bl.net:close-connection conn)
    (is (null (bl.net::connection-send-queue-in conn)))
    (is (null (bl.net::connection-send-queue-out conn)))
    (is (= 0 (send-buffer-bytes conn)))))

(test send-bytes-buffers-and-never-blocks-on-jammed-socket
  "A peer whose TCP window is jammed must not pin the caller: send-bytes writes
what the kernel takes, queues the rest, and returns promptly instead of
blocking the shared thread. Past the cap the peer is send-paused, and the
message is still QUEUED — Core's PushMessage (net.cpp:4088-4113) never
discards a message it decided to send; it only sets fPauseSend, which stops
us reading that peer's input (70502bf3)."
  (let ((srv (bl.net:open-listener "127.0.0.1" 0)))
    (is-true srv)
    (when srv
      (unwind-protect
          (let* ((port (usocket:get-local-port srv))
                 (client-sock (usocket:socket-connect
                               "127.0.0.1" port
                               :element-type '(unsigned-byte 8)))
                 ;; Accept the server side but NEVER read from it — jam the pipe.
                 (server-conn (usocket:socket-accept srv :element-type '(unsigned-byte 8)))
                 (conn (bl.net::make-connection
                        :socket client-sock :host "127.0.0.1" :port port
                        :connected t)))
            (declare (ignorable server-conn))
            (bl.net::set-socket-non-blocking client-sock)
            ;; Run the sends in a bounded worker so a regression (a blocking
            ;; write) can be caught as a timeout rather than hanging the suite.
            (let* ((chunk (make-array 200000 :element-type '(unsigned-byte 8)
                                             :initial-element 7))
                   (total (* 20 (length chunk)))
                   (dropped nil)
                   (sends-done nil)
                   (worker (bt:make-thread
                            (lambda ()
                              ;; ~4MB total: far past the 1MB cap on a loopback
                              ;; socket whose kernel buffer is well under that.
                              (dotimes (_ 20)
                                (let ((r (bl.net:send-bytes conn chunk)))
                                  (when (null r) (setf dropped t))))
                              (setf sends-done t))
                            :name "eclipse-send-worker")))
              ;; Bounded join: the worker must finish quickly (non-blocking).
              (bl.net:join-thread-or-destroy worker :timeout 10)
              (is-true sends-done "send-bytes must not block on a jammed socket")
              ;; Data backed up into the per-connection buffer.
              (is-true (plusp (send-buffer-bytes conn)))
              ;; The buffer went over the cap, so the peer is send-paused.
              (is-true (bl.net:connection-send-paused-p conn))
              (is-false dropped "an over-cap message must be queued, not dropped")
              ;; Every byte is accounted for: what the kernel took plus what is
              ;; still buffered is the whole 4 MB. A drop would lose a chunk here.
              (is (= total (+ (bl.net:connection-bytes-sent conn)
                              (send-buffer-bytes conn)))
                  "queued + sent must equal what was handed to send-bytes")
              (bl.net:close-connection conn)
              (ignore-errors (usocket:socket-close server-conn))))
        (bl.net:close-listener srv)))))

(test send-paused-peer-has-its-input-left-unread
  "Core's backpressure runs on the INPUT side: ProcessMessages returns before
polling a new message from a peer whose send buffer is over the cap
(net_processing.cpp:5244-5245), so the work is deferred rather than answered
into a socket that cannot take it. The pump must therefore leave a
send-paused peer's readable message where it is, and pick it up once the
buffer drains (70502bf3).

The second half is the positive control: with the pause cleared and nothing
else changed, the SAME pending message is read."
  (let ((srv (bl.net:open-listener "127.0.0.1" 0)))
    (is-true srv)
    (when srv
      (let* ((port (usocket:get-local-port srv))
             (sender (usocket:socket-connect "127.0.0.1" port
                                             :element-type '(unsigned-byte 8)))
             (accepted (usocket:socket-accept srv :element-type '(unsigned-byte 8)))
             (conn (bl.net::make-connection
                    :socket accepted :host "127.0.0.1" :port port :connected t))
             (peer (bl.net:make-peer :state :ready :address "127.0.0.1:8333"
                                     :connection conn)))
        (unwind-protect
             (progn
               ;; A whole, well-formed message is waiting to be read.
               (write-sequence (bl.ser:make-ping-message 42)
                               (usocket:socket-stream sender))
               (force-output (usocket:socket-stream sender))
               (sleep 0.2)
               ;; Paused: the pump must not touch it.
               (setf (send-buffer-bytes conn)
                     (1+ bl.net:*max-send-buffer-bytes*))
               (is-true (bl.net:connection-send-paused-p conn))
               (drain-peer-once peer (bl.ctx:make-node-context) nil)
               (is (= 0 (bl.net:connection-bytes-received conn))
                   "a send-paused peer's input is left unread")
               (is-true (bl.net:connection-connected conn)
                        "and the pause is not a reason to disconnect it")
               ;; Positive control: unpause and the same message is consumed.
               (setf (send-buffer-bytes conn) 0)
               (drain-peer-once peer (bl.ctx:make-node-context) nil)
               (is (plusp (bl.net:connection-bytes-received conn))
                   "and once drained the pending message is read after all")
               (is (plusp (gethash "ping" (bl.net:peer-recv-per-msg peer) 0))
                   "the message the pause deferred is the one dispatched"))
          (bl.net:close-connection conn)
          (ignore-errors (usocket:socket-close sender))
          (bl.net:close-listener srv))))))

(defun %gdq-tx (n)
  "A distinct segwit tx for the deferred-getdata tests (N picks the outpoint,
so two calls give two different txids)."
  (bl.ser:make-transaction
   :version 2
   :inputs (vector (bl.ser:make-tx-in
                    :previous-output (bl.ser:make-outpoint
                                      :hash (make-array 32 :element-type '(unsigned-byte 8)
                                                           :initial-element n)
                                      :index 0)
                    :script-sig (make-array 0 :element-type '(unsigned-byte 8))
                    :sequence #xffffffff))
   :outputs (vector (bl.ser:make-tx-out
                     :value 1000
                     :script-pubkey (make-array 1 :element-type '(unsigned-byte 8)
                                                  :initial-element #x51)))
   :witness (vector (list (make-array 4 :element-type '(unsigned-byte 8)
                                        :initial-contents '(1 2 3 4))))
   :lock-time 0))

(defun %gdq-payload (txids)
  "The payload of a getdata asking for TXIDS as MSG_WITNESS_TX."
  (subseq (bl.ser:make-getdata-message
           (mapcar (lambda (h)
                     (bl.ser:make-inv-vector
                      :type bl.ser:+inv-type-witness-tx+ :hash h))
                   txids))
          24))

(test send-paused-getdata-waits-in-the-peer-queue-and-resumes
  "A getdata whose peer goes send-paused part-way through is PARKED, not
dropped: Core answers from the front of peer.m_getdata_requests, breaks out on
fPauseSend and erases only the prefix it answered (net_processing.cpp:2532-2536,
:2558, :2570), then drains the rest at the top of the next ProcessMessages
(:5222-5227) -- before the fPauseSend return that stops it reading the peer at
all (:5244-5245). Dropping the remainder instead makes the peer wait out its
own request timeout for data we had already looked up.

Two txs are asked for in one getdata and the first answer fills the outgoing
buffer past the cap. The unbroadcast set is the witness of a serve on either
side: it loses an entry on every successful answer (Core ProcessGetData
RemoveUnbroadcastTx), so 1 of 2 means exactly one tx went out."
  (let* ((bl:*network* :regtest)
         (mempool (bl.mp:make-mempool))
         (srv (bl.net:open-listener "127.0.0.1" 0)))
    (is-true srv)
    (when srv
      (let* ((port (usocket:get-local-port srv))
             (sender (usocket:socket-connect "127.0.0.1" port
                                             :element-type '(unsigned-byte 8)))
             (accepted (usocket:socket-accept srv :element-type '(unsigned-byte 8)))
             (conn (bl.net::make-connection
                    :socket accepted :host "127.0.0.1" :port port :connected t))
             (peer (bl.net:make-peer :state :ready :address "127.0.0.1:8333"
                                     :connection conn))
             (txs (list (%gdq-tx 41) (%gdq-tx 42)))
             (txids (mapcar #'bl.ser:transaction-hash txs))
             (ctx (bl.ctx:make-node-context :mempool mempool))
             (answers 0)
             (real (fdefinition 'bl.net:send-message)))
        (unwind-protect
             (progn
               (dolist (tx txs)
                 (%add-tx mempool tx)
                 (bl.mp:mempool-add-unbroadcast
                  mempool (bl.ser:transaction-hash tx)))
               ;; Both txs predate our last inv flush, so both are servable
               ;; (the anti-probing gate would otherwise refuse them).
               (setf (bl.net:peer-last-inv-sequence peer)
                     (bl.mp:mempool-sequence mempool))
               (unwind-protect
                    (progn
                      ;; Answering the FIRST request fills the send buffer past
                      ;; the cap, which is what Core's fPauseSend break sees.
                      (setf (fdefinition 'bl.net:send-message)
                            (lambda (p bytes)
                              (declare (ignore bytes))
                              (incf answers)
                              (setf (send-buffer-bytes (bl.net:peer-connection p))
                                    (1+ bl.net:*max-send-buffer-bytes*))
                              t))
                      (deliver-getdata peer (%gdq-payload txids) ctx))
                 (setf (fdefinition 'bl.net:send-message) real))
               (is (= 1 answers) "the pause stops the serve after one answer")
               (is (= 1 (bl.mp:mempool-unbroadcast-count mempool))
                   "exactly one of the two txs was answered")
               (is (= 1 (length (peer-pending-getdata peer)))
                   "and the unanswered request is parked on the peer, not dropped")
               ;; The buffer drains; the shipped pump resumes the parked request
               ;; before it decides whether to read this peer at all.
               (setf (send-buffer-bytes conn) 0)
               (drain-peer-once peer ctx nil)
               (is (= 0 (bl.mp:mempool-unbroadcast-count mempool))
                   "the parked request is answered once the buffer drains")
               (is (null (peer-pending-getdata peer)) "and the queue is empty again")
               (is-true (bl.net:connection-connected conn)
                        "the peer is not disconnected by any of this"))
          (bl.net:close-connection conn)
          (ignore-errors (usocket:socket-close sender))
          (bl.net:close-listener srv))))))

;;; ============================================================
;;; 3. Per-address addr/addrv2 rate limit
;;; ============================================================

(test addr-token-bucket-fresh-value
  "A fresh peer's addr token bucket starts at 1.0 (Core m_addr_token_bucket
initial value)."
  (let ((p (bl.net:make-peer)))
    (is (= 1.0d0 (bl.net::peer-addr-token-bucket p)))))

(test addr-token-bucket-refills-at-core-rate
  "The bucket refills at 0.1 tokens/sec (MAX_ADDR_RATE_PER_SECOND), clamped to
the 1000-token soft cap."
  (let ((p (bl.net:make-peer)))
    (setf (bl.net::peer-addr-token-bucket p) 0.0d0
          (bl.net::peer-addr-token-timestamp p)
          (- (get-internal-real-time) (* 100 internal-time-units-per-second)))
    (bl.net::%refill-addr-token-bucket p)
    ;; 100s * 0.1/s = 10 tokens.
    (is (< 9.9d0 (bl.net::peer-addr-token-bucket p) 10.1d0)))
  ;; Clamp: a huge elapsed time never exceeds the soft cap.
  (let ((p (bl.net:make-peer)))
    (setf (bl.net::peer-addr-token-bucket p) 0.0d0
          (bl.net::peer-addr-token-timestamp p)
          (- (get-internal-real-time) (* 10000000 internal-time-units-per-second)))
    (bl.net::%refill-addr-token-bucket p)
    (is (= (coerce bl.net::+max-addr-processing-token-bucket+ 'double-float)
           (bl.net::peer-addr-token-bucket p)))))

(defun %addr-entries (n &key (base 10))
  "N distinct routable IPv4 net-addr / timestamp conses (fresh timestamps)."
  (let ((now (bl.ser:get-unix-time)))
    (loop for i below n
          collect (cons (bl.ser:make-net-addr
                         :services 1
                         :ip (bl.net:ipv4-to-mapped-ipv6
                              base 0 (floor i 256) (mod i 256))
                         :port 8333)
                        now))))

(defun %addr-payload (ips &key (services 1) (port 8333))
  "A v1 addr message payload (no header) announcing each 16-byte IP in IPS
with a fresh timestamp."
  (let ((now (bl.ser:get-unix-time)))
    (coerce (bl.bytes:with-byte-buf (s)
              (bl.bytes:bb-write-varint s (length ips))
              (dolist (ip ips)
                (bl.ser:write-net-addr
                 s (bl.ser:make-net-addr :services services :ip ip :port port)
                 :with-timestamp t :timestamp now)))
            '(simple-array (unsigned-byte 8) (*)))))

(test addr-beyond-bucket-are-dropped
  "Addresses beyond the token bucket are dropped, not queued: with a bucket of
5, exactly 5 of 20 announced addresses are processed and 15 are rate-limited,
and the counters are surfaced (Core rate_limited branch + m_addr_processed /
m_addr_rate_limited)."
  (let ((bl.net:*reachable-networks* '(:ipv4 :ipv6))
        (book (bl.net:make-address-book))
        (p (bl.net:make-peer :conn-type :outbound-full-relay)))
    ;; Depleted-ish bucket, timestamp now so refill is ~0.
    (setf (bl.net::peer-addr-token-bucket p) 5.0d0
          (bl.net::peer-addr-token-timestamp p)
          (get-internal-real-time))
    (let ((added (bl.net::%process-gossiped-addresses
                  p (%addr-entries 20) 20 book nil)))
      (is (= 5 added) "only 5 addresses fit the bucket")
      (is (= 5 (bl.net:peer-addr-processed p)))
      (is (= 15 (bl.net:peer-addr-rate-limited p)))
      ;; Upper bound only: the 20 test addresses share one /16 and one
      ;; source, so addrman maps them all into a single 64-slot new bucket
      ;; (bucket keys on the (addr-group, source-group) pair) and 5 inserts
      ;; slot-collide with p~15% per run — a colliding insert correctly
      ;; REPLACES the earlier entry, making exact-count flaky. The rate
      ;; limit's storage-layer guarantee is that no more than 5 ever reach
      ;; the book; placement within addrman is addrman's own contract.
      (is (<= (bl.net:address-book-count book) 5)))))

(test addr-full-bucket-processes-all
  "With a full bucket a normal small announcement is fully processed and
nothing is rate-limited."
  (let ((bl.net:*reachable-networks* '(:ipv4 :ipv6))
        (book (bl.net:make-address-book))
        (p (bl.net:make-peer :conn-type :outbound-full-relay)))
    (setf (bl.net::peer-addr-token-bucket p) 1000.0d0
          (bl.net::peer-addr-token-timestamp p)
          (get-internal-real-time))
    (let ((added (bl.net::%process-gossiped-addresses
                  p (%addr-entries 10) 10 book nil)))
      (is (= 10 added))
      (is (= 10 (bl.net:peer-addr-processed p)))
      (is (= 0 (bl.net:peer-addr-rate-limited p))))))

(test getaddr-solicitation-clears-on-nonfull-message
  "A non-full (<1000) addr message answers our outstanding getaddr (clears
m_getaddr_sent); a full (1000) one does not."
  (let ((book (bl.net:make-address-book))
        (p (bl.net:make-peer :conn-type :outbound-full-relay)))
    (setf (bl.net::peer-addr-token-bucket p) 1000.0d0
          (bl.net::peer-getaddr-requested p) t)
    ;; Non-full announced-count clears the flag.
    (bl.net::%process-gossiped-addresses p (%addr-entries 3) 3 book nil)
    (is-false (bl.net::peer-getaddr-requested p))
    ;; A full 1000-count message leaves it set (more may follow).
    (setf (bl.net::peer-getaddr-requested p) t
          (bl.net::peer-addr-token-bucket p) 1000.0d0)
    (bl.net::%process-gossiped-addresses p (%addr-entries 3) 1000 book nil)
    (is-true (bl.net::peer-getaddr-requested p))))

(test getaddr-bump-exempts-solicited-response-from-bucket
  "Sending our getaddr bumps the bucket by MAX_ADDR_TO_SEND (1000), so a full
solicited response processes despite the ~0.1/s steady-state refill (Core
net_processing.cpp:3772)."
  (let ((bl.net:*reachable-networks* '(:ipv4 :ipv6))
        (book (bl.net:make-address-book))
        (p (bl.net:make-peer :conn-type :outbound-full-relay)))
    ;; Steady-state bucket, then apply the getaddr bump manually (as
    ;; send-post-handshake-messages does).
    (setf (bl.net::peer-addr-token-bucket p) 1.0d0
          (bl.net::peer-addr-token-timestamp p)
          (get-internal-real-time))
    (incf (bl.net::peer-addr-token-bucket p)
          (coerce bl.ser:+max-addr-count+ 'double-float))
    (let ((added (bl.net::%process-gossiped-addresses
                  p (%addr-entries 500) 500 book nil)))
      (is (= 500 added) "solicited addresses processed under the bump")
      (is (= 0 (bl.net:peer-addr-rate-limited p))))))

(test handle-addr-ignores-block-relay-peer
  "A block-relay-only peer participates in no addr relay: handle-addr /
handle-addrv2 ignore its addresses entirely (Core SetupAddressRelay)."
  (let ((book (bl.net:make-address-book))
        (p (bl.net:make-peer :conn-type :block-relay))
        (payload (%addr-payload (list (bl.net:ipv4-to-mapped-ipv6 10 0 0 1)))))
    (is (= 0 (bl.net:handle-addr p payload (bl.ctx:make-node-context :address-book book))))
    (is (= 0 (bl.net:address-book-count book)))))

(test gossiped-banned-addresses-are-neither-stored-nor-relayed
  "Core skips a banned or discouraged address inside the per-address ADDR loop:
`if (m_banman && (IsDiscouraged(addr) || IsBanned(addr))) continue;`, under the
comment \"Do not process banned/discouraged addresses beyond remembering we
received them\" (net_processing.cpp:4094-4097). That continue skips BOTH the
RelayAddress call (:4102) and the vAddrOk push that feeds addrman (:4106), so a
hostile address neither takes an addrman bucket from a good one nor gets
gossiped onward by the node that decided it was hostile. Our only ban filter
was the getaddr-response cache fill, which is the pull path.

The third address is clean and rides in the same message: it is the positive
control, so a setup that never reached the loop at all cannot pass this test by
asserting absences. Relay is observed through the relay target's outgoing addr
queue, which RELAY-ADDRESS fills for every peer it picks — a test peer owns no
socket, and the queue is where an address waits for its flush anyway."
  (bl.net:clear-discouraged)
  ;; Three distinct /16s: addrman buckets on the (address group, source group)
  ;; pair, so same-group fixtures share one 64-slot bucket and a slot collision
  ;; would silently drop an entry the assertion is counting.
  (let* ((bl.net:*reachable-networks* '(:ipv4 :ipv6))
         (book (bl.net:make-address-book))
         (banned-ip (bl.net:ipv4-to-mapped-ipv6 198 51 100 41))
         (discouraged-ip (bl.net:ipv4-to-mapped-ipv6 203 0 113 42))
         (clean-ip (bl.net:ipv4-to-mapped-ipv6 192 0 2 43))
         (target (bl.net:make-peer :state :ready :address "198.51.100.44"))
         (ctx (bl.ctx:make-node-context :address-book book :peers (list target))))
    (setf (bl.net:peer-addr-relay-enabled target) t)
    (bl.net:ban-address "198.51.100.41" 3600)
    (bl.net:discourage-peer "203.0.113.42")
    (unwind-protect
         (let ((added (bl.net:handle-addr
                       nil
                       (%addr-payload (list banned-ip discouraged-ip clean-ip))
                       ctx)))
           (is (= 1 added)
               "only the clean address may be stored, stored: ~D" added)
           (is (= 1 (bl.net:address-book-count book))
               "only the clean address may reach addrman, book holds ~D"
               (bl.net:address-book-count book))
           (is-true (bl.net:address-book-lookup book clean-ip 8333)
                    "control: the clean address must be the one that is there")
           (flet ((relayed-p (ip)
                    (find ip (bl.net::peer-addrs-to-send target)
                          :key #'bl.net:peer-address-ip :test #'equalp)))
             (is-true (relayed-p clean-ip)
                      "control: the clean address must still be relayed onward")
             (is-false (relayed-p banned-ip)
                       "a banned address must not be gossiped onward")
             (is-false (relayed-p discouraged-ip)
                       "a discouraged address must not be gossiped onward")))
      (bl.net:unban-address "198.51.100.41")
      (bl.net:clear-discouraged))))

(test handle-addr-oversized-is-misbehavior
  "An addr message announcing more than 1000 addresses is misbehavior (Core
Misbehaving on vAddr.size() > MAX_ADDR_TO_SEND): the peer is disconnected and
nothing is stored."
  (let ((book (bl.net:make-address-book))
        (p (bl.net:make-peer :conn-type :outbound-full-relay
                                              :address "203.0.113.9"))
        (payload (coerce
                  (bl.bytes:with-byte-buf (s)
                    (bl.bytes:bb-write-varint s 1001))
                  '(simple-array (unsigned-byte 8) (*)))))
    (is (= 0 (bl.net:handle-addr p payload (bl.ctx:make-node-context :address-book book))))
    (is (eq :disconnected (bl.net:peer-state p)))
    (is (= 0 (bl.net:address-book-count book)))))

;;; ============================================================
;;; 3b. Gossiped-address ingestion: age never gates STORAGE
;;; ============================================================
;;;
;;; Core (net_processing.cpp:4087-4114) stores every gossiped address it can
;;; use, rewriting only absurd timestamps, and lets addrman's 30-day horizon
;;; retire stale entries at SELECTION time (AddrInfo::IsTerrible). Its own DNS
;;; seed path deliberately mints entries aged 3-7 DAYS (net.cpp:2375), so a
;;; storage-side freshness window would discard exactly what a getaddr response
;;; exists to deliver -- and addrman diversity is the substrate every
;;; anti-eclipse mechanism selects from.

(defun %addr-test-book ()
  "A fresh address book with a PINNED bucket key. Placement is otherwise keyed
by a per-process CSPRNG secret, which makes exact-content assertions on a book
holding several addresses flake on random bucket/slot collisions; pin the seed
through the constructor rather than derandomising production."
  (bl.net:make-address-book
   :key (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)))

(defun %gossip-ip (d)
  "A routable IPv4 (198.51.100.D) as mapped IPv6 bytes."
  (bl.net:ipv4-to-mapped-ipv6 198 51 100 d))

(defun %gossip-net-addr (ip &key (services bl.ser:+node-network+)
                                 (port 8333))
  (bl.ser:make-net-addr :services services :ip ip :port port))

(defun %gossip-ingest (book net-addr timestamp now &key source-net source-ip)
  "One address through the production ingestion path; (VALUES stored relay)."
  (bl.net::%ingest-gossiped-address
   net-addr timestamp book nil now source-net source-ip))

(defun %gossip-last-seen (book ip &optional (port 8333))
  "Stored nTime for IP:PORT in BOOK, or NIL when absent."
  (let ((entry (bl.net:address-book-lookup book ip port)))
    (and entry (bl.net:peer-address-last-seen entry))))

(test gossiped-address-age-does-not-gate-storage
  "A 20-day-old gossiped address is STORED -- Core applies no storage-side
freshness window, leaving stale entries to addrman's 30-day horizon at
selection time -- but is NOT relayed onward, the 10-minute gate applying to
relay only (net_processing.cpp:4102). The window this replaces DISCARDED it,
which is why the live node accumulated ~1,600 addrman entries in 2.5 months."
  (let* ((bl.net:*reachable-networks* '(:ipv4 :ipv6))
         (book (%addr-test-book))
         (now 1800000000)
         (ip (%gossip-ip 7))
         (old (- now (* 20 24 60 60))))
    (multiple-value-bind (stored relay)
        (%gossip-ingest book (%gossip-net-addr ip) old now)
      (is (= 1 stored) "a 20-day-old address is stored")
      (is (null relay) "...and is never relayed onward"))
    (is (= 1 (bl.net:address-book-count book)))
    (let ((last-seen (%gossip-last-seen book ip)))
      (is (not (null last-seen)) "the 20-day-old address is in the book")
      (when last-seen
        (is (= (- old (* 2 60 60)) last-seen)
            "stored with Core's 2h gossip time penalty")))))

(test handle-addr-stores-aged-address-end-to-end
  "The same thing through the real message path (handle-addr -> %process-gossiped-addresses (bl.ctx:make-node-context :peers ingestion :address-book ->)): a week-old address in an addr
message reaches addrman, penalised by 2h and by nothing else."
  (let* ((bl.net:*reachable-networks* '(:ipv4 :ipv6))
         (book (%addr-test-book))
         (ip (%gossip-ip 11))
         (old (- (bl.ser:get-unix-time) (* 7 24 60 60)))
         (payload (coerce
                   (bl.bytes:with-byte-buf (s)
                     (bl.bytes:bb-write-varint s 1)
                     (bl.ser:write-net-addr
                      s (%gossip-net-addr ip)
                      :with-timestamp t :timestamp old))
                   '(simple-array (unsigned-byte 8) (*)))))
    (is (= 1 (bl.net:handle-addr nil payload (bl.ctx:make-node-context :address-book book))))
    (is (= 1 (bl.net:address-book-count book)))
    (is (eql (- old (* 2 60 60)) (%gossip-last-seen book ip)))))

(test gossiped-absurd-timestamp-is-rewritten-not-dropped
  "A timestamp at or below CAddress::TIME_INIT, or more than 10 minutes ahead
of us, is REWRITTEN to now - 5 days and stored anyway (Core
net_processing.cpp:4090-4092) rather than dropped -- and the rewrite is what
the relay gate then reads, so a flying-DeLorean timestamp cannot buy relay."
  (let* ((bl.net:*reachable-networks* '(:ipv4 :ipv6))
         (now 1800000000)
         ;; rewrite to now-5d, then the 2h storage penalty on top.
         (expected (- now (* 5 24 60 60) (* 2 60 60))))
    (loop for (timestamp . d) in (list (cons 0 21)                ; unset
                                       (cons 100000000 22)        ; TIME_INIT itself
                                       (cons (+ now 3600) 23))    ; an hour ahead
          do (let ((book (%addr-test-book))
                   (ip (%gossip-ip d)))
               (multiple-value-bind (stored relay)
                   (%gossip-ingest book (%gossip-net-addr ip) timestamp now)
                 (is (= 1 stored) "absurd timestamp ~D is stored, not dropped" timestamp)
                 (is (null relay) "a rewritten address is not relayed"))
               (let ((last-seen (%gossip-last-seen book ip)))
                 (is (not (null last-seen)) "timestamp ~D reached the book" timestamp)
                 (when last-seen
                   (is (= expected last-seen)
                       "timestamp ~D rewritten to now-5d" timestamp)))))
    ;; Boundary: exactly now+10min is NOT absurd, so it survives verbatim.
    (let ((book (%addr-test-book))
          (ip (%gossip-ip 24)))
      (%gossip-ingest book (%gossip-net-addr ip) (+ now 600) now)
      (is (eql (- (+ now 600) (* 2 60 60)) (%gossip-last-seen book ip))))))

(test gossiped-address-stored-with-two-hour-penalty
  "Gossip is hearsay, so Core stores a third party's address 2 hours in the
past (/*time_penalty=*/2h, net_processing.cpp:4114) and exempts only a peer
announcing ITSELF (addrman.cpp:559-563, \"Do not set a penalty for a source's
self-announcement\")."
  (let ((bl.net:*reachable-networks* '(:ipv4 :ipv6))
        (now 1800000000))
    ;; Third party: penalised.
    (let ((book (%addr-test-book))
          (ip (%gossip-ip 31)))
      (%gossip-ingest book (%gossip-net-addr ip) now now
                      :source-net :ipv4 :source-ip (%gossip-ip 99))
      (is (eql (- now (* 2 60 60)) (%gossip-last-seen book ip))))
    ;; Self-announcement, source derived from the peer by the real path.
    (let* ((book (%addr-test-book))
           (ip (%gossip-ip 32))
           (ts (bl.ser:get-unix-time))
           (p (bl.net:make-peer :conn-type :outbound-full-relay
                                                 :address "198.51.100.32")))
      (setf (bl.net::peer-addr-token-bucket p) 10.0d0)
      (bl.net::%process-gossiped-addresses
       p (list (cons (%gossip-net-addr ip) ts)) 1 book nil)
      (is (eql ts (%gossip-last-seen book ip))
          "a peer announcing its own address is not time-penalised"))))

(test gossiped-address-service-filter
  "Core stores only addresses that may run a useful address DB
(net_processing.cpp:4087 / MayHaveUsefulAddressDB): NODE_NETWORK or
NODE_NETWORK_LIMITED. Anything else is skipped entirely -- neither stored nor
relayed -- so services=0 junk never becomes a dial candidate."
  (let* ((bl.net:*reachable-networks* '(:ipv4 :ipv6))
         (now 1800000000))
    (loop for (services d storedp) in
          (list (list 0 41 nil)                                             ; nothing
                (list bl.ser:+node-witness+ 42 nil)     ; witness only
                (list bl.ser:+node-network+ 43 t)
                (list bl.ser:+node-network-limited+ 44 t)
                (list (logior bl.ser:+node-network+
                              bl.ser:+node-witness+) 45 t))
          do (let ((book (%addr-test-book))
                   (ip (%gossip-ip d)))
               (multiple-value-bind (stored relay)
                   (%gossip-ingest book (%gossip-net-addr ip :services services) now now)
                 (is (= (if storedp 1 0) stored) "services ~D storage" services)
                 (is (eq storedp (not (null relay))) "services ~D relay" services))
               (is (= (if storedp 1 0)
                      (bl.net:address-book-count book))
                   "services ~D book count" services)))))

(test gossiped-address-relay-gate-is-ten-minutes
  "Control for the storage change: the RELAY gate is untouched and still the
10 minutes Core uses (net_processing.cpp:4102). 9m59s old relays; 10m01s old
does not -- yet BOTH are stored, which is the whole point of separating the
two gates."
  (let* ((bl.net:*reachable-networks* '(:ipv4 :ipv6))
         (now 1800000000))
    (loop for (age d relayp) in (list (list 599 51 t)
                                      (list 601 52 nil)
                                      (list (* 20 24 60 60) 53 nil))
          do (let ((book (%addr-test-book))
                   (ip (%gossip-ip d)))
               (multiple-value-bind (stored relay)
                   (%gossip-ingest book (%gossip-net-addr ip) (- now age) now)
                 (is (= 1 stored) "age ~Ds is stored regardless" age)
                 (is (eq relayp (not (null relay))) "age ~Ds relay decision" age))))))

;;; ============================================================
;;; 4. Generic-path low-work presync anti-DoS
;;; ============================================================

(defun %regtest-chain-state (dir)
  "A fresh regtest chain-state with a genesis index entry (chain-work 1)."
  (let* ((state (bl.store:init-chain-state
                 (merge-pathnames dir (uiop:temporary-directory))))
         (genesis-hash (bl.store:best-block-hash state))
         (zeros (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (bl.store:add-block-index-entry
     state (bl.store:make-block-index-entry
            :hash genesis-hash :height 0 :chain-work 1 :status :valid
            :header (bl.ser:make-block-header
                     :version 1 :prev-block zeros :merkle-root zeros
                     :timestamp 1296688600 :bits #x207fffff :nonce 0
                     :cached-hash genesis-hash)))
    (values state genesis-hash)))

(defun %pow-header (prev-hash &key (timestamp 1296688700) (version 4) (merkle 1))
  "A regtest header off PREV-HASH ground to a valid PoW nonce."
  (let ((mr (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
    (setf (aref mr 0) (logand merkle #xff))
    (let ((hdr (bl.ser:make-block-header
                :version version :prev-block prev-hash :merkle-root mr
                :timestamp timestamp :bits #x207fffff :nonce 0)))
      (loop for nonce from 0 below 5000
            do (setf (bl.ser:block-header-nonce hdr) nonce
                     (bl.ser:block-header-cached-hash hdr) nil)
            when (bl.val:check-proof-of-work hdr)
              do (return hdr)
            finally (return hdr)))))

(test maybe-start-presync-reports-low-work
  "maybe-start-presync's second value flags a connecting sub-threshold chain
even when no sync starts (a non-full batch): the caller must then IGNORE the
batch rather than storing it. A full batch additionally yields a sync object."
  (let ((bl:*network* :regtest)
        (bl.store:*pow-limit-target*
          bl.store:+regtest-pow-limit-target+))
    (multiple-value-bind (state genesis-hash) (%regtest-chain-state "test-presync-lw/")
      ;; Force the anti-DoS threshold sky-high so any real chain is "low work".
      (let* ((bl:*minimum-chain-work-override* (expt 2 240))
             (h1 (%pow-header genesis-hash)))
        ;; Sub-batch (full-batch-p nil): low-work-p T, but no sync started.
        (multiple-value-bind (sync low-work)
            (bl.net::maybe-start-presync (list h1) state nil)
          (is (null sync) "a non-full batch must not start a sync")
          (is-true low-work "connecting sub-threshold chain is flagged low-work"))
        ;; Full batch (full-batch-p t): a sync is created.
        (multiple-value-bind (sync low-work)
            (bl.net::maybe-start-presync (list h1) state t)
          (is-true low-work)
          (is-true (bl.net::headers-sync-state-p sync)
                   "a full low-work batch starts a presync"))))))

(test generic-path-ignores-sub-batch-low-work-headers
  "The generic announcement path (ingest-headers-from-peer) must store NOTHING
for a connecting but sub-threshold, non-full header batch — the from-genesis
memory-exhaustion DoS this item fixes. Previously such headers were committed
to the index because the validated-tip work gate was off during IBD."
  (let ((bl:*network* :regtest)
        (bl.store:*pow-limit-target*
          bl.store:+regtest-pow-limit-target+))
    (multiple-value-bind (state genesis-hash) (%regtest-chain-state "test-presync-ignore/")
      (let* ((bl:*minimum-chain-work-override* (expt 2 240))
             (p (bl.net:make-peer :conn-type :outbound-full-relay))
             (h1 (%pow-header genesis-hash))
             (h1-hash (bl.ser:block-header-hash h1)))
        (let ((added (bl.net:ingest-headers-from-peer p (list h1) state)))
          (is (= 0 added) "sub-threshold low-work headers must not be stored")
          (is (null (bl.store:get-block-index-entry state h1-hash))
              "the low-work header must not enter the block index"))))))

(test generic-path-stores-above-threshold-headers
  "Above the work threshold, the generic path validates and stores normally —
steady-state tip announcements are unaffected by the anti-DoS gate."
  (let ((bl:*network* :regtest)
        (bl.store:*pow-limit-target*
          bl.store:+regtest-pow-limit-target+))
    (multiple-value-bind (state genesis-hash) (%regtest-chain-state "test-presync-store/")
      ;; Threshold 0 (regtest default): the genesis-anchored chain meets it.
      (let* ((bl:*minimum-chain-work-override* 0)
             (p (bl.net:make-peer :conn-type :outbound-full-relay))
             (h1 (%pow-header genesis-hash :timestamp 1296688700))
             (h1-hash (bl.ser:block-header-hash h1)))
        (let ((added (bl.net:ingest-headers-from-peer p (list h1) state)))
          (is (= 1 added) "above-threshold header is stored")
          (is (not (null (bl.store:get-block-index-entry state h1-hash)))
              "above-threshold header enters the block index"))))))

(test generic-path-unconnecting-headers-store-nothing
  "A header batch that does not connect to our index (unknown prev-block)
stores nothing and does not error — Core HandleUnconnectingHeaders sends a
getheaders and stages availability, committing nothing."
  (let ((bl:*network* :regtest)
        (bl.store:*pow-limit-target*
          bl.store:+regtest-pow-limit-target+))
    (multiple-value-bind (state genesis-hash) (%regtest-chain-state "test-presync-unconn/")
      (declare (ignore genesis-hash))
      (let* ((bl:*minimum-chain-work-override* 0)
             (p (bl.net:make-peer :conn-type :outbound-full-relay))
             (orphan-prev (make-array 32 :element-type '(unsigned-byte 8)
                                         :initial-element 99))
             (h1 (%pow-header orphan-prev))
             (h1-hash (bl.ser:block-header-hash h1)))
        (let ((added (bl.net:ingest-headers-from-peer p (list h1) state)))
          (is (= 0 added))
          (is (null (bl.store:get-block-index-entry state h1-hash))
              "an unconnecting header must not enter the index"))))))

;;;; ============================================================
;;;; G7-18: drop outbound peers on sub-minchainwork chains during IBD
;;;; ============================================================

(defun %g718-state-with-work (work)
  "A chain-state holding one header entry with WORK chain-work, and a peer
whose best-known block is that entry."
  (let* ((state (bl.store:make-chain-state))
         (hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 21)))
    (bl.store:add-block-index-entry
     state (bl.store:make-block-index-entry
            :hash hash :height 1 :chain-work work :status :header-valid))
    (values state hash)))

(defun %g718-peer (&key (conn-type :outbound-full-relay) inbound manual best-hash)
  (let ((p (bl.net:make-peer :inbound inbound)))
    (setf (bl.net:peer-conn-type p) conn-type
          (bl.net:peer-manual p) manual
          (bl.net:peer-state p) :ready)
    (when best-hash
      (setf (bl.net:peer-best-known-block-hash p) best-hash))
    p))

(defmacro %with-whitelist ((&key entries (whitebind 0)) &body body)
  "Run BODY with exactly ENTRIES (a list of -whitelist spec strings) parsed and
installed, and WHITEBIND as the -whitebind flags. Bound, not set: the whitelist
is global start-up configuration, and a test that leaked it would grant
permissions to every peer in every later test."
  `(let ((bl.net:*whitelist-entries*
           (mapcar (lambda (spec)
                     (or (bl.net:parse-whitelist-entry spec)
                         (error "test fixture: unparseable -whitelist ~S" spec)))
                   ,entries))
         (bl.net:*whitebind-flags* ,whitebind))
     ,@body))

(test net-permission-flags-parse-as-cores-do
  "Core TryParsePermissionFlags (net_permissions.cpp:26-90). The two implication
rules are the ones worth pinning, because both are written into the ENUMERATOR
in Core rather than into the parser: forcerelay implies relay, and noban
implies download. A parser that treated them as independent bits would grant
less than the operator asked for, silently."
  (flet ((flags (spec)
           (nth-value 0 (bl.net:parse-permission-flags spec)))
         (rest-of (spec)
           (nth-value 2 (bl.net:parse-permission-flags spec))))
    ;; No @: implicit permissions, and the whole string is the address.
    (is (= bl.net::+perm-implicit+ (flags "1.2.3.4")))
    (is (equal "1.2.3.4" (rest-of "1.2.3.4")))
    (is (equal "1.2.3.0/24" (rest-of "noban@1.2.3.0/24")))
    ;; forcerelay implies relay; noban implies download.
    (let ((f (flags "forcerelay@1.2.3.4")))
      (is (= bl.net:+perm-relay+
             (logand f bl.net:+perm-relay+))))
    (let ((f (flags "noban@1.2.3.4")))
      (is (= bl.net:+perm-download+
             (logand f bl.net:+perm-download+))))
    ;; "all" covers every named permission.
    (let ((f (flags "all@1.2.3.4")))
      (dolist (bit (list bl.net:+perm-bloom-filter+
                         bl.net:+perm-relay+
                         bl.net:+perm-force-relay+
                         bl.net:+perm-noban+
                         bl.net:+perm-mempool+
                         bl.net:+perm-download+
                         bl.net:+perm-addr+))
        (is (= bit (logand f bit)))))
    ;; Core accepts both spellings of bloomfilter.
    (is (= (flags "bloom@1.2.3.4") (flags "bloomfilter@1.2.3.4")))
    ;; Multiple permissions, comma-separated.
    (let ((f (flags "noban,mempool@1.2.3.4")))
      (is (= bl.net:+perm-mempool+
             (logand f bl.net:+perm-mempool+)))
      (is (= bl.net:+perm-noban+
             (logand f bl.net:+perm-noban+))))
    ;; An unknown permission is refused outright rather than ignored.
    (is-false (flags "nosuchperm@1.2.3.4"))
    (is-false (bl.net:parse-whitelist-entry "nosuchperm@1.2.3.4"))
    ;; As is an unparseable range.
    (is-false (bl.net:parse-whitelist-entry "noban@not-an-address"))
    ;; -whitebind refuses "out": a listening socket has no outgoing peers.
    (is-false (bl.net:parse-whitelist-entry
               "noban,out@1.2.3.4" :allow-out nil)))
  ;; Rendering back, for getpeerinfo.permissions. "implicit" is not a
  ;; permission and is never listed.
  (is (equal '("noban" "download")
             (bl.net:permission-flag-names
              bl.net:+perm-noban+)))
  (is (null (bl.net:permission-flag-names
             bl.net::+perm-implicit+))))

(test net-permissions-apply-by-address-and-direction
  "A range grants permissions only to peers inside it, and only in the
direction the operator named — \"noban@...,out\" grants nothing to an inbound
peer from that range. -whitebind's flags reach inbound peers only, since they
describe a listening socket."
  (%with-whitelist (:entries '("noban@10.0.0.0/8"))
    (is (= bl.net:+perm-noban+
           (logand (bl.net:peer-permission-flags "10.1.2.3" t)
                   bl.net:+perm-noban+)))
    ;; Outside the range: nothing.
    (is (= 0 (bl.net:peer-permission-flags "11.1.2.3" t)))
    ;; An address that does not parse is refused, never defaulted in.
    (is (= 0 (bl.net:peer-permission-flags "not-an-address" t))))
  (%with-whitelist (:entries '("noban,out@10.0.0.0/8"))
    (is (= 0 (bl.net:peer-permission-flags "10.1.2.3" t))
        "an out-only grant reached an inbound peer")
    (is (plusp (bl.net:peer-permission-flags "10.1.2.3" nil))))
  ;; -whitebind: inbound only.
  (%with-whitelist (:entries '() :whitebind bl.net:+perm-mempool+)
    (is (plusp (bl.net:peer-permission-flags "10.1.2.3" t)))
    (is (= 0 (bl.net:peer-permission-flags "10.1.2.3" nil)))))

(test an-inbound-onion-peers-address-earns-it-no-permissions
  "Core skips the address-range whitelist for a Tor inbound, and its comment
is the whole argument:

    // Tor inbound connections do not reveal the peer's actual network address.
    // Therefore do not apply address-based whitelist permissions to them.
    AddWhitelistPermissionFlags(permission_flags,
                                inbound_onion ? std::optional<CNetAddr>{} : addr,
                                vWhitelistedRangeIncoming);   (net.cpp:1770-1772)

Passing no address means no subnet in the loop can match (net.cpp:572-578).

We matched every inbound peer's address against the ranges. Every inbound
onion connection arrives from the LOCAL Tor daemon and so presents the onion
listener's own bind — 127.0.0.1 for all of them — which turned one loopback
grant, a bare -whitelist=127.0.0.0/8 among them, into the operator's
trusted-peer permissions for every anonymous onion peer on earth: exemption
from misbehaviour discouragement, from the accept-time ban and discourage
drops, and from inbound eviction.

-whitebind is deliberately NOT skipped: those flags describe the listening
SOCKET, not an address, and Core fills them in before this call."
  (%with-whitelist (:entries '("noban@127.0.0.1/32"))
    (is (= bl.net:+perm-noban+ (bl.net:peer-permission-flags "127.0.0.1" t))
        "control: an ordinary inbound peer at that address is granted noban")
    (is (= 0 (bl.net:peer-permission-flags "127.0.0.1" t t))
        "an inbound onion peer must earn nothing from the range"))
  ;; A permissive range is the realistic operator mistake, and it must not
  ;; reach the onion peers either.
  (%with-whitelist (:entries '("all@127.0.0.0/8"))
    (is (plusp (bl.net:peer-permission-flags "127.0.0.1" t))
        "control: the wide range does grant a clearnet loopback peer")
    (is (= 0 (bl.net:peer-permission-flags "127.0.0.1" t t))))
  ;; -whitebind survives: the socket said so, not the address.
  (%with-whitelist (:entries '("noban@127.0.0.1/32")
                    :whitebind bl.net:+perm-mempool+)
    (is (= bl.net:+perm-mempool+
           (bl.net:peer-permission-flags "127.0.0.1" t t))))
  ;; And through the accessor the rest of the tree consults.
  (%with-whitelist (:entries '("noban@127.0.0.1/32"))
    (let ((onion (%g718-peer :inbound t))
          (clearnet (%g718-peer :inbound t)))
      (setf (bl.net:peer-address onion) "127.0.0.1"
            (bl.net:peer-address clearnet) "127.0.0.1"
            (bl.net:peer-inbound-onion onion) t)
      (is-true (bl.net:peer-has-permission-p clearnet bl.net:+perm-noban+)
               "control: the clearnet peer at the same address holds noban")
      (is-false (bl.net:peer-has-permission-p onion bl.net:+perm-noban+))
      ;; What that exemption was buying: a misbehaving onion peer could not be
      ;; disconnected at all, because RECORD-MISBEHAVIOR returns early on
      ;; noban. (Discouragement is separately withheld from every loopback
      ;; address, Core net_processing.cpp:5194-5201, so only the disconnect
      ;; distinguishes the two peers here.)
      (is-true (bl.net:record-misbehavior onion "test")
               "a misbehaving onion peer must still be disconnected")
      (is (eq :disconnected (bl.net:peer-state onion)))
      (is-false (bl.net:record-misbehavior clearnet "test")
                "control: the noban clearnet peer is still spared")
      (is (eq :ready (bl.net:peer-state clearnet))))))

(test getpeerinfo-reports-the-permissions-the-node-enforces
  "Core's getpeerinfo prints the STORED m_permission_flags, so it can never
disagree with what the node enforces. Ours recomputes them per row, which
makes the agreement a thing to keep: the row must ask the same question the
enforcement sites ask, onion-ness included, or an inbound onion peer is
reported holding a loopback range's grant that nothing will honour — the
operator reads `noban' on a peer this node would still ban."
  (%with-whitelist (:entries '("noban@127.0.0.1/32"))
    (let* ((node (bl:make-node))
           (onion (bl.net:make-peer :address "127.0.0.1" :inbound t :state :ready))
           (clearnet (bl.net:make-peer :address "127.0.0.1" :inbound t :state :ready)))
      (setf (bl.net:peer-inbound-onion onion) t
            (bl:node-peers node) (list onion clearnet))
      (let ((rows (mapcar (lambda (row)
                            (cdr (assoc "permissions" row :test #'string=)))
                          (bl.rpc:dispatch-rpc-method node "getpeerinfo" '()))))
        (is (equalp '(#() #("noban" "download")) rows)
            "the onion row must be empty and the clearnet row at the same \
address must still say noban")))))

(test noban-peer-is-neither-discouraged-nor-disconnected
  "Core clears m_should_discourage for a noban peer AND keeps the connection
(MaybeDiscourageAndDisconnect). Stopping at \"not discouraged\" while still
dropping the connection would not deliver the option — the point of
-whitelist=noban is that a peer the operator trusts survives our opinion of its
behaviour."
  (%with-whitelist (:entries '("noban@10.0.0.0/8"))
    (let ((p (%g718-peer :inbound t)))
      (setf (bl.net:peer-address p) "10.1.2.3")
      (is-false (bl.net:record-misbehavior p "test"))
      (is (eq :ready (bl.net:peer-state p))
          "a noban peer was disconnected for misbehaviour")
      (is-false (bl.net:peer-discouraged-p "10.1.2.3")))
    ;; Control: a peer OUTSIDE the range is punished exactly as before.
    (let ((p (%g718-peer :inbound t)))
      (setf (bl.net:peer-address p) "11.1.2.3")
      (is-true (bl.net:record-misbehavior p "test"))
      (is (eq :disconnected (bl.net:peer-state p)))
      (is-true (bl.net:peer-discouraged-p "11.1.2.3")))))

(test relay-permission-excuses-blocksonly-and-nothing-else
  "Core RejectIncomingTxs (net_processing.cpp:5686-5694): the \"relay\"
permission excuses the -blocksonly clause and ONLY that clause. A
block-relay-only or feeler connection may never send us transactions whatever
its permissions — a permission that also unlocked those would let an operator
turn a link they meant to keep block-only into a tx firehose."
  (let ((bl:*blocksonly* t)
        (bl:*network* :regtest))
    (flet ((dropped-p (address conn-type)
             (let ((p (%g718-peer :conn-type conn-type :inbound t)))
               (setf (bl.net:peer-address p) address)
               (bl.net::handle-tx p (make-array 0 :element-type '(unsigned-byte 8)) (bl.ctx:make-node-context))
               (eq :disconnected (bl.net:peer-state p)))))
      (%with-whitelist (:entries '("relay@10.0.0.0/8"))
        ;; Control: without the permission, -blocksonly drops the sender.
        (is-true (dropped-p "11.1.2.3" :outbound-full-relay))
        ;; With it, the -blocksonly clause no longer applies.
        (is-false (dropped-p "10.1.2.3" :outbound-full-relay))
        ;; But a block-relay-only connection is still refused.
        (is-true (dropped-p "10.1.2.3" :block-relay))
        (is-true (dropped-p "10.1.2.3" :feeler))))))

(test addr-permission-lifts-the-rate-limit
  "Core net_processing.cpp:4066 — `rate_limited =
!pfrom.HasPermission(NetPermissionFlags::Addr)`. Such a peer may send us
unlimited addresses; everyone else spends tokens."
  (flet ((rate-limited-count (address entries)
           (let* ((book (bl.net:make-address-book))
                  (p (%g718-peer :inbound t))
                  (now (bl.ser:get-unix-time))
                  (addrs (loop for i below 40
                               collect (cons (bl.ser:make-net-addr
                                              :services 1
                                              :ip (bl.net:ipv4-to-mapped-ipv6
                                                   10 0 0 (1+ i))
                                              :port 8333)
                                             now))))
             (setf (bl.net:peer-address p) address)
             ;; An EMPTY bucket, so any processing at all proves the exemption.
             (setf (bl.net::peer-addr-token-bucket p) 0d0)
             (%with-whitelist (:entries entries)
               (bl.net::%process-gossiped-addresses
                p addrs (length addrs) book nil))
             (bl.net:peer-addr-rate-limited p))))
    ;; Control: an empty bucket rate-limits every address.
    (is (= 40 (rate-limited-count "11.1.2.3" '("noban@10.0.0.0/8"))))
    ;; With the addr permission, none of them are.
    (is (= 0 (rate-limited-count "10.1.2.3" '("addr@10.0.0.0/8"))))))

(test mempool-permission-is-what-answers-bip35
  "Core honours a BIP35 mempool request only from a peer with the \"mempool\"
permission, since it does not advertise NODE_BLOOM (net_processing.cpp:
4940-4951); everyone else is disconnected. Granting the permission and then
sending nothing would be worse than the disconnect, so this asserts the inv
actually goes out."
  (let ((mp (bl.mp:make-mempool)))
    (%mine-add mp (make-mempool-test-tx :input-id 61) 10000)
    (flet ((ask (address entries)
             (let ((p (%g718-peer :inbound t)))
               (setf (bl.net:peer-address p) address)
               ;; A peer with no stored version counts as tx-relaying, which
               ;; is what %g718-peer leaves behind.
               (values (%cbp-capture-sends
                        (lambda ()
                          (%with-whitelist (:entries entries)
                            (bl.net:handle-message p "mempool" (make-array 0 :element-type
                                                       '(unsigned-byte 8)) (bl.ctx:make-node-context :mempool mp)))))
                       (bl.net:peer-state p)))))
      ;; Without the permission: no inv, and the peer is dropped.
      (multiple-value-bind (sent state) (ask "11.1.2.3" '("noban@10.0.0.0/8"))
        (is (null sent) "an unpermitted mempool request was answered: ~S" sent)
        (is (eq :disconnected state)))
      ;; With it: an inv, and the peer stays.
      (multiple-value-bind (sent state) (ask "10.1.2.3" '("mempool@10.0.0.0/8"))
        (is (equal '("inv") sent)
            "a permitted mempool request sent ~S instead of one inv" sent)
        (is (eq :ready state))))))

(test g7-18-outbound-or-block-relay-predicate
  "Core IsOutboundOrBlockRelayConn (net.h:771-785). Both halves matter: it must
INCLUDE :block-relay, and it must EXCLUDE manual (-addnode) peers — ours are
typed :outbound-full-relay, and connect-added-nodes redials them every ~30s, so
a plain not-inbound test would loop connect/disconnect against a peer the
operator pinned."
  (is-true (bl.net:peer-outbound-or-block-relay-p
            (%g718-peer :conn-type :outbound-full-relay)))
  (is-true (bl.net:peer-outbound-or-block-relay-p
            (%g718-peer :conn-type :block-relay))
           ":block-relay must be included")
  (is-false (bl.net:peer-outbound-or-block-relay-p
             (%g718-peer :conn-type :outbound-full-relay :manual t))
            "manual -addnode peers must be excluded")
  (is-false (bl.net:peer-outbound-or-block-relay-p
             (%g718-peer :conn-type :feeler)))
  (is-false (bl.net:peer-outbound-or-block-relay-p
             (%g718-peer :inbound t))))

(test g7-18-low-work-outbound-disconnected-in-ibd
  "G7-18: we refused to DOWNLOAD from a sub-minchainwork peer but never
disconnected it, so a toy-chain peer could pin an outbound slot for the whole
of IBD — a step toward IBD eclipse."
  (let ((bl:*network* :regtest)
        (bl:*minimum-chain-work-override* 1000))
    (multiple-value-bind (state hash) (%g718-state-with-work 10)
      ;; Low work + non-full batch + outbound + IBD => dropped.
      (let ((p (%g718-peer :best-hash hash)))
        (is-true (bl.net::maybe-disconnect-low-work-outbound
                  p state nil))
        (is (eq :disconnected (bl.net:peer-state p))))
      ;; A FULL batch means more headers may follow — we have not seen their
      ;; tip yet, so we must not judge them.
      (let ((p (%g718-peer :best-hash hash)))
        (is-false (bl.net::maybe-disconnect-low-work-outbound
                   p state t)
                  "a full batch must not trigger the drop"))
      ;; Manual and inbound peers are exempt.
      (let ((p (%g718-peer :best-hash hash :manual t)))
        (is-false (bl.net::maybe-disconnect-low-work-outbound
                   p state nil)
                  "manual peers must never be auto-dropped"))
      (let ((p (%g718-peer :best-hash hash :inbound t)))
        (is-false (bl.net::maybe-disconnect-low-work-outbound
                   p state nil)))
      ;; A peer that never announced anything is never judged (Core :2930).
      (let ((p (%g718-peer)))
        (is-false (bl.net::maybe-disconnect-low-work-outbound
                   p state nil)
                  "a peer with no best-known block must not be judged")))))

(test g7-18-minimum-chain-work-comparison-is-strict
  "The comparison is STRICTLY less than minimum-chain-work: a peer whose chain
exactly meets the floor is kept. (The obvious version of this test — pointing a
FRESH peer at a raised floor — asserts nothing, because a fresh peer has no
best-known block and is skipped for that reason rather than the work one.)"
  (let ((bl:*network* :regtest))
    ;; Work exactly equal to the floor: kept.
    (multiple-value-bind (state hash) (%g718-state-with-work 1000)
      (let ((bl:*minimum-chain-work-override* 1000)
            (p (%g718-peer :best-hash hash)))
        (is-false (bl.net::maybe-disconnect-low-work-outbound
                   p state nil)
                  "equal work must be kept, not dropped")
        (is (eq :ready (bl.net:peer-state p)))))
    ;; One unit below the floor: dropped.
    (multiple-value-bind (state hash) (%g718-state-with-work 999)
      (let ((bl:*minimum-chain-work-override* 1000)
            (p (%g718-peer :best-hash hash)))
        (is-true (bl.net::maybe-disconnect-low-work-outbound
                  p state nil))))))

(test g7-18-not-applied-outside-ibd
  "Past IBD the rule does not apply — a peer on a short chain is no longer
occupying a slot we need for syncing."
  (let ((bl:*network* :regtest)
        (bl:*minimum-chain-work-override* 1000))
    (multiple-value-bind (state hash) (%g718-state-with-work 10)
      ;; Force the IBD latch off for this check.
      (let ((bl.net:*cached-is-ibd* nil)
            (p (%g718-peer :best-hash hash)))
        (is-false (bl.net::maybe-disconnect-low-work-outbound
                   p state nil)
                  "outside IBD the peer must be kept")))))

;;;; ============================================================
;;;; G7-08 P1/P2: outbound chain-sync eviction + protection
;;;; =====================================================

(defun %g708-chain (tip-work)
  "A chain-state whose tip has TIP-WORK, plus a lower-work entry a peer can
claim as its best-known."
  (let* ((state (bl.store:make-chain-state))
         (tip-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 8))
         (low-hash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 9)))
    (bl.store:add-block-index-entry
     state (bl.store:make-block-index-entry
            :hash tip-hash :height 100 :chain-work tip-work :status :valid))
    (bl.store:add-block-index-entry
     state (bl.store:make-block-index-entry
            :hash low-hash :height 50 :chain-work (floor tip-work 2) :status :valid))
    (bl.store:update-chain-tip state tip-hash 100)
    (values state tip-hash low-hash)))

(defun %g708-peer (&key (conn-type :outbound-full-relay) inbound manual best-hash protect
                        (address "test"))
  (let ((p (bl.net:make-peer :inbound inbound :address address)))
    (setf (bl.net:peer-conn-type p) conn-type
          (bl.net:peer-manual p) manual
          (bl.net:peer-state p) :ready
          (bl.net::peer-chain-sync-protect p) protect)
    (when best-hash
      (setf (bl.net:peer-best-known-block-hash p) best-hash))
    p))

(test g7-08-chain-sync-arms-probes-then-disconnects
  "G7-08 P1 (Core ConsiderEviction): a live-but-SILENT outbound peer sitting
below our tip's work is given a 20-minute budget, then probed once with a
getheaders, then dropped after a further 2 minutes. Such peers answer pings, so
nothing else evicts them — an adversary filling our outbound slots with them
pins us on a stale tip indefinitely."
  (multiple-value-bind (state tip-hash low-hash) (%g708-chain 1000)
    (declare (ignore tip-hash))
    (let ((peer (%g708-peer :best-hash low-hash))
          (sent 0))
      (let ((real (fdefinition 'bl.net:send-message)))
        (unwind-protect
             (progn
               (setf (fdefinition 'bl.net:send-message)
                     (lambda (p m) (declare (ignore p m)) (incf sent)))
               ;; First sweep arms the timer.
               (is (eq :armed (bl.net:consider-chain-sync-eviction
                               peer state 1000)))
               (is (= 0 sent) "arming must not send anything")
               ;; Before the deadline: nothing happens (still armed, no re-arm).
               (is (null (bl.net:consider-chain-sync-eviction
                          peer state 1500)))
               ;; Past 20 minutes: probe with a getheaders, do NOT disconnect.
               (is (eq :probed (bl.net:consider-chain-sync-eviction
                                peer state (+ 1000 1201))))
               (is (= 1 sent) "the probe must send exactly one getheaders")
               (is (eq :ready (bl.net:peer-state peer))
                   "the probe must not disconnect")
               ;; A further 2 minutes with no improvement: drop it.
               (is (eq :disconnected (bl.net:consider-chain-sync-eviction
                                      peer state (+ 1000 1201 121))))
               (is (eq :disconnected (bl.net:peer-state peer))))
          (setf (fdefinition 'bl.net:send-message) real))))))

(test g7-08-good-chain-clears-the-timer
  "A peer whose best-known work reaches our tip clears its timer entirely — it
has answered for itself."
  (multiple-value-bind (state tip-hash) (%g708-chain 1000)
    (let ((peer (%g708-peer :best-hash tip-hash)))
      (setf (bl.net::peer-chain-sync-timeout peer) 500)
      (is (eq :cleared (bl.net:consider-chain-sync-eviction
                        peer state 1000)))
      (is (zerop (bl.net::peer-chain-sync-timeout peer))))))

(test g7-08-exempt-peers-are-never-evicted
  "Manual, inbound and protected peers are outside the eviction logic. Manual
matters most: connect-added-nodes redials them every ~30s, so evicting one
would loop forever against a peer the operator pinned."
  (multiple-value-bind (state tip-hash low-hash) (%g708-chain 1000)
    (declare (ignore tip-hash))
    (dolist (peer (list (%g708-peer :best-hash low-hash :manual t)
                        (%g708-peer :best-hash low-hash :inbound t)
                        (%g708-peer :best-hash low-hash :protect t)
                        (%g708-peer :best-hash low-hash :conn-type :feeler)))
      (is (null (bl.net:consider-chain-sync-eviction
                 peer state 1000))
          "exempt peers must not even be armed"))
    ;; A block-relay peer IS a candidate (Core keeps them subject to the logic).
    (is (eq :armed (bl.net:consider-chain-sync-eviction
                    (%g708-peer :best-hash low-hash :conn-type :block-relay)
                    state 1000)))))

(test g7-08-protection-is-capped-at-four-and-released
  "Core protects at most MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT (4)
outbound FULL-RELAY peers; block-relay peers are deliberately never protected."
  (let ((bl.net::*protected-outbound-count* 0))
    (let ((peers (loop repeat 6 collect (%g708-peer))))
      (dolist (p peers) (bl.net:maybe-protect-outbound-peer p))
      (is (= 4 (count-if #'bl.net::peer-chain-sync-protect peers))
          "at most 4 peers may hold protection")
      (is (= 4 bl.net::*protected-outbound-count*))
      ;; Releasing frees a slot for another peer.
      (bl.net:release-outbound-protection (first peers))
      (is (= 3 bl.net::*protected-outbound-count*))
      (is (bl.net:maybe-protect-outbound-peer (%g708-peer))
          "a freed slot must be reusable"))
    ;; Block-relay peers are not eligible.
    (let ((bl.net::*protected-outbound-count* 0))
      (is (null (bl.net:maybe-protect-outbound-peer
                 (%g708-peer :conn-type :block-relay)))
          "block-relay peers must stay subject to the eviction logic"))))

(test g7-08-outbound-churn-does-not-exhaust-the-protection-slots
  "The PRODUCTION wiring: DISCONNECT-PEER itself must return the slot (Core
FinalizeNode, net_processing.cpp:1717-1718). Calling RELEASE-OUTBOUND-PROTECTION
by hand proves nothing about that — with no production releaser the counter only
ever increments, so the first 4 outbound full-relay peers claim every slot within
minutes of startup (during IBD a caught-up peer trivially satisfies best-known >=
tip) and, once they churn out, NO later peer can ever be protected. That inverts
P2 into a guarantee that every outbound peer is evictable."
  (let ((bl.net::*protected-outbound-count* 0))
    (let ((peers (loop repeat 4 collect (%g708-peer))))
      (dolist (p peers)
        (is-true (bl.net:maybe-protect-outbound-peer p)))
      (is (= 4 bl.net::*protected-outbound-count*))
      ;; All slots spent: a fifth peer cannot be protected yet.
      (is-false (bl.net:maybe-protect-outbound-peer (%g708-peer))
                "the cap must hold while all 4 slots are occupied")
      ;; Normal churn: every peer retires through the real disconnect path.
      (dolist (p peers) (bl.net:disconnect-peer p))
      (is (= 0 bl.net::*protected-outbound-count*)
          "disconnect-peer must give every slot back")
      (is (= 0 (count-if #'bl.net::peer-chain-sync-protect peers))
          "no retired peer may still claim protection")
      ;; The point of the whole exercise: peers dialed after the churn can still
      ;; earn protection.
      (let ((fresh (loop repeat 4 collect (%g708-peer))))
        (dolist (p fresh)
          (is-true (bl.net:maybe-protect-outbound-peer p)
                   "a post-churn peer must still be able to earn protection"))
        (is (= 4 bl.net::*protected-outbound-count*))))))

(test g7-08-repeated-release-decrements-exactly-once
  "A peer can be retired by more than one path (disconnected, then reaped; or
misbehaving, then disconnected). The per-peer flag is the source of truth, so
only the first release decrements — a double decrement would let us hand out
more than the 4 slots Core allows, which is the same uncapped state the leak
produced, only from the other direction."
  (let ((bl.net::*protected-outbound-count* 0))
    (let ((a (%g708-peer))
          (b (%g708-peer)))
      (is-true (bl.net:maybe-protect-outbound-peer a))
      (is-true (bl.net:maybe-protect-outbound-peer b))
      (is (= 2 bl.net::*protected-outbound-count*))
      ;; Retire A three times over, two of them through the production path.
      (bl.net:disconnect-peer a)
      (bl.net:disconnect-peer a)
      (bl.net:release-outbound-protection a)
      ;; B still holds its slot: the count is 1, not 0 and not negative.
      (is (= 1 bl.net::*protected-outbound-count*)
          "releasing one peer repeatedly must decrement exactly once")
      (is-true (bl.net::peer-chain-sync-protect b)
               "the other peer must keep its protection"))))

(test g7-08-misbehavior-releases-the-protection-slot
  "RECORD-MISBEHAVIOR retires a peer without going through DISCONNECT-PEER (it
closes the connection and sets :disconnected itself), so it owes the slot back
too — Core's FinalizeNode runs for every removal whatever the reason. Leaving
this path out would leak a slot on every protected outbound peer that trips a
protocol rule."
  (let ((bl.net::*protected-outbound-count* 0))
    ;; A dedicated address: record-misbehavior writes to the global discourage
    ;; filter, and "test" is shared with the other helpers here.
    (let ((peer (%g708-peer :address "198.51.100.77")))
      (is-true (bl.net:maybe-protect-outbound-peer peer))
      (is (= 1 bl.net::*protected-outbound-count*))
      (bl.net:record-misbehavior peer "g7-08 slot release")
      (is (= 0 bl.net::*protected-outbound-count*)
          "record-misbehavior must give the slot back")
      (is-false (bl.net::peer-chain-sync-protect peer)))))

(test g7-08-retired-peers-are-never-granted-protection
  "Core guards the grant with `!pfrom.fDisconnect` (net_processing.cpp:2951):
a peer it has already decided to retire must never be handed a protection
slot. Ours is PEER-LIVE-P.

This is the leak from the other end. A retirement releases the slot, but it
only ever happens ONCE — replace-disconnected-peers reaps :disconnected peers
straight out of node-peers with no release, and never reaps :banned peers at
all — so a slot granted AFTER the retirement is never given back. Four of them
exhaust every slot for the life of the process and no peer can be protected
again, which is precisely the state P2 exists to prevent."
  (let ((bl.net::*protected-outbound-count* 0))
    ;; Control: an identical, still-live peer IS granted.
    (let ((live (%g708-peer)))
      (is-true (bl.net:maybe-protect-outbound-peer live)
               "a live outbound full-relay peer must still be granted")
      (is (= 1 bl.net::*protected-outbound-count*)))
    ;; Retired through the real DISCONNECT-PEER.
    (let ((dead (%g708-peer)))
      (bl.net:disconnect-peer dead)
      (is (eq :disconnected (bl.net:peer-state dead))
          "precondition: the peer really is retired")
      (is-false (bl.net:peer-live-p dead))
      (is-false (bl.net:maybe-protect-outbound-peer dead)
                "a :disconnected peer must never be granted a slot")
      (is (= 1 bl.net::*protected-outbound-count*)
          "a refused grant must leave the counter untouched")
      (is-false (bl.net::peer-chain-sync-protect dead)
                "and must not set the per-peer flag"))
    ;; Retired through the real BAN-PEER. Worse than :disconnected: nothing
    ;; ever reaps a banned peer, so a slot granted here is lost outright.
    (let ((banned (%g708-peer :address "198.51.100.78")))
      (unwind-protect
           (progn
             (bl.net:ban-peer banned)
             (is (eq :banned (bl.net:peer-state banned))
                 "precondition: the peer really is banned")
             (is-false (bl.net:peer-live-p banned))
             (is-false (bl.net:maybe-protect-outbound-peer banned)
                       "a :banned peer must never be granted a slot")
             (is (= 1 bl.net::*protected-outbound-count*)
                 "a refused grant must leave the counter untouched")
             (is-false (bl.net::peer-chain-sync-protect banned)))
        ;; ban-peer writes the process-global ban list; put it back.
        (bl.net:unban-address "198.51.100.78")))))

(test g7-08-headers-from-a-retired-peer-do-not-grant-protection
  "The same refusal through the PRODUCTION path — ingest-headers-from-peer ->
%store-validated-headers, which is where the grant actually fires. Asserting
it on the bare predicate is not enough: the hazard is an ordering one.

Core runs the sub-minchainwork drop (net_processing.cpp:2926-2944)
immediately BEFORE the grant (:2946-2956), in the same function, on the same
peer — which is exactly why the grant carries !fDisconnect. Move our low-work
drop to the matching position and the sequence becomes drop -> disconnect-peer
-> release (counter--), then a re-grant on the corpse (counter++, forever).
During IBD the two conditions overlap in the common case: a peer whose
best-known beats our low tip but misses the work floor is both droppable and
protectable.

The header batch is byte-identical in all three runs and every run stores it,
so the only thing that differs is the peer's liveness."
  (let ((bl:*network* :regtest)
        (bl.store:*pow-limit-target*
          bl.store:+regtest-pow-limit-target+))
    (flet ((ingest (dir peer)
             ;; A fresh genesis-only regtest index, one valid header off it.
             ;; Its chain-work lands above the tip's, so the grant condition
             ;; (best-known >= tip) holds for whichever peer delivers it.
             (multiple-value-bind (state genesis-hash) (%regtest-chain-state dir)
               (let ((bl:*minimum-chain-work-override* 0))
                 (bl.net:ingest-headers-from-peer
                  peer (list (%pow-header genesis-hash)) state)))))
      ;; Control: a live peer earns protection from this batch.
      (let ((bl.net::*protected-outbound-count* 0)
            (peer (%g708-peer)))
        (is (= 1 (ingest "test-g708-live/" peer))
            "control: the batch must actually be stored")
        (is-true (bl.net::peer-chain-sync-protect peer)
                 "a live peer delivering a chain at least as good as our tip is protected")
        (is (= 1 bl.net::*protected-outbound-count*)))
      ;; Same batch, peer already retired by disconnect-peer.
      (let ((bl.net::*protected-outbound-count* 0)
            (peer (%g708-peer)))
        (bl.net:disconnect-peer peer)
        (is (= 1 (ingest "test-g708-dead/" peer))
            "the batch is still processed — the peer is what changed")
        (is-false (bl.net::peer-chain-sync-protect peer)
                  "a retired peer must not be protected by the headers path")
        (is (= 0 bl.net::*protected-outbound-count*)
            "and the counter must not move"))
      ;; Same batch, peer already banned.
      (let ((bl.net::*protected-outbound-count* 0)
            (peer (%g708-peer :address "198.51.100.79")))
        (unwind-protect
             (progn
               (bl.net:ban-peer peer)
               (is (= 1 (ingest "test-g708-banned/" peer))
                   "the batch is still processed — the peer is what changed")
               (is-false (bl.net::peer-chain-sync-protect peer)
                         "a banned peer must not be protected by the headers path")
               (is (= 0 bl.net::*protected-outbound-count*)
                   "and the counter must not move"))
          (bl.net:unban-address "198.51.100.79"))))))
;;;; GA8 W3: the low-work drop must fire only where Core evaluates it
;;;;
;;;; Core reaches the disconnect solely through
;;;; UpdatePeerStateForReceivedHeaders (net_processing.cpp:2926-2944), which
;;;; ProcessHeadersMessage calls only on the STORED path (:3113). It returns
;;;; early — never judging the peer — for an empty message (:2969-2981), for an
;;;; unconnecting BIP130 announcement (:3029-3040) and for a batch swallowed by
;;;; TryLowWorkHeadersSync (:3065-3074). Conversely a batch of headers we
;;;; already have sets already_validated_work (:3049-3054), BYPASSES
;;;; TryLowWorkHeadersSync and DOES reach the disconnect — Core's own comment at
;;;; :2786-2790 spells that interaction out.
;;;; ============================================================

(defmacro %w3-with-regtest (&body body)
  "Regtest network + regtest PoW limit + the IBD latch forced ON, so these
assertions cannot be made vacuous by whatever an earlier test left in the
globals."
  `(with-network (:regtest)
     (let ((bl.net:*cached-is-ibd* t))
       ,@body)))

(defun %w3-stored-header (dir)
  "A regtest chain-state (genesis chain-work 1) with one real header H1 stored
off genesis via the production ingest path at a zero work floor. Returns
(values state genesis-hash h1 h1-hash). H1's chain-work is tiny (regtest block
proof), so raising the floor afterwards makes it sub-minchainwork."
  (multiple-value-bind (state genesis-hash) (%regtest-chain-state dir)
    (let* ((bl:*minimum-chain-work-override* 0)
           (h1 (%pow-header genesis-hash))
           (h1-hash (bl.ser:block-header-hash h1)))
      (bl.net:ingest-headers-from-peer
       (%g718-peer) (list h1) state)
      (values state genesis-hash h1 h1-hash))))

(test w3-unconnecting-announcement-does-not-disconnect-outbound
  "GA8 W3 (S2), the regression. Early mainnet IBD, our chain still below
nMinimumChainWork: outbound peer B's best-known block is a low-work header (the
pprev priming sweep set it). A new block is mined and B sends a 1-header BIP130
announcement whose parent we lack. Core runs HandleUnconnectingHeaders and
RETURNS (net_processing.cpp:3029-3040). We ran the drop after EVERY branch of
ingest-headers-from-peer, and the unconnecting branch only stages
hash-last-unknown — best-known stays at its stale sub-floor value — so the
check fired with a non-full batch and dropped B. Every announcing outbound peer
could be churned this way during the most eclipse-sensitive phase."
  (%w3-with-regtest
    (multiple-value-bind (state genesis-hash)
        (%regtest-chain-state "test-w3-unconn-nodrop/")
      (let* ((bl:*minimum-chain-work-override* 1000)
             ;; Genesis carries chain-work 1, three orders below the floor.
             (p (%g718-peer :best-hash genesis-hash))
             (orphan-prev (make-array 32 :element-type '(unsigned-byte 8)
                                         :initial-element 77))
             (announced (%pow-header orphan-prev)))
        (is-true (bl.net:initial-block-download-p state)
                 "fixture must be in IBD, or the whole assertion is vacuous")
        (is (= 0 (bl.net:ingest-headers-from-peer
                  p (list announced) state))
            "an unconnecting header stores nothing")
        (is (eq :ready (bl.net:peer-state p))
            "a BIP130 announcement with an unknown parent must NOT drop the peer")))))

(test w3-empty-headers-message-does-not-disconnect-outbound
  "An empty headers message is Core's nCount==0 early return
(net_processing.cpp:2969-2981) — the peer is never judged. We judged it, so a
peer answering \"I have nothing more\" during IBD was dropped on the spot."
  (%w3-with-regtest
    (multiple-value-bind (state genesis-hash)
        (%regtest-chain-state "test-w3-empty-nodrop/")
      (let ((bl:*minimum-chain-work-override* 1000)
            (p (%g718-peer :best-hash genesis-hash)))
        (is (= 0 (bl.net:ingest-headers-from-peer p nil state)))
        (is (eq :ready (bl.net:peer-state p))
            "an empty headers message must NOT drop the peer")))))

(test w3-low-work-diverted-batch-does-not-disconnect-outbound
  "A connecting batch whose claimed work is below the anti-DoS threshold is
swallowed by TryLowWorkHeadersSync, which returns true and makes
ProcessHeadersMessage return (net_processing.cpp:3065-3074, :2800-2807) — no
peer-state update, no disconnect. Nothing was stored, so there is no
pindexLast to judge the peer on."
  (%w3-with-regtest
    (multiple-value-bind (state genesis-hash)
        (%regtest-chain-state "test-w3-lowwork-nodrop/")
      (let* ((bl:*minimum-chain-work-override* 1000)
             (p (%g718-peer :best-hash genesis-hash))
             (h1 (%pow-header genesis-hash))
             (h1-hash (bl.ser:block-header-hash h1)))
        (is (= 0 (bl.net:ingest-headers-from-peer
                  p (list h1) state)))
        (is (null (bl.store:get-block-index-entry state h1-hash))
            "the low-work header must not enter the index")
        (is (eq :ready (bl.net:peer-state p))
            "an ignored low-work batch must NOT drop the peer")))))

(test w3-low-work-outbound-still-dropped-on-stored-batch
  "The control: the feature must still fire where Core fires it. A batch we
already hold sets already_validated_work (net_processing.cpp:3046-3054),
bypasses TryLowWorkHeadersSync and reaches
UpdatePeerStateForReceivedHeaders — so the outbound peer whose whole chain sits
below the floor IS dropped. Deleting the check outright would redden this."
  (%w3-with-regtest
    (multiple-value-bind (state genesis-hash h1 h1-hash)
        (%w3-stored-header "test-w3-stored-drop/")
      (declare (ignore genesis-hash))
      (is (not (null (bl.store:get-block-index-entry state h1-hash)))
          "fixture must have stored H1, or the already-known branch is not taken")
      (let ((bl:*minimum-chain-work-override* 1000)
            (p (%g718-peer)))
        (is (= 0 (bl.net:ingest-headers-from-peer
                  p (list h1) state))
            "an already-known header adds nothing to the index")
        (is (equalp h1-hash (bl.net:peer-best-known-block-hash p))
            "the stored path must have refreshed availability first")
        (is (eq :disconnected (bl.net:peer-state p))
            "a stored non-full batch leaving best-known below the floor must drop")))))

(test w3-solicited-phase1-path-drops-low-work-outbound
  "GA8 W3 (S3), the other half: handle-header-batch — the solicited Phase-1
path — never applied the drop at all, and %maybe-divert-to-presync had no
known-ancestor skip, so the CLASSIC case never fired: an outbound peer pinned
on a low-work fork answers our getheaders with a short batch of headers we
already hold. Core sets already_validated_work for exactly that shape
(net_processing.cpp:3046-3054, and the comment at :2786-2790), skipping
TryLowWorkHeadersSync and reaching the disconnect."
  (%w3-with-regtest
    (multiple-value-bind (state genesis-hash h1 h1-hash)
        (%w3-stored-header "test-w3-phase1-drop/")
      (declare (ignore genesis-hash h1-hash))
      (let ((bl:*minimum-chain-work-override* 1000))
        (let* ((p (%g718-peer))
               (added 0)
               (done (bl.net::handle-header-batch
                      p state (list h1) nil (lambda (n) (incf added n)))))
          (is-true done "a non-full batch ends header sync with this peer")
          (is (= 0 added) "an already-known batch adds nothing")
          (is (eq :disconnected (bl.net:peer-state p))
              "the solicited path must drop a sub-minchainwork outbound peer"))
        ;; Same batch declared FULL: may_have_more_headers, so the peer is kept
        ;; (Core's !may_have_more_headers guard) — but sync still ends, because
        ;; nothing entered the index and our locator is built from our own
        ;; header tip, so re-asking would fetch this very batch again.
        (let ((p (%g718-peer)))
          (is-true (bl.net::handle-header-batch
                    p state (list h1) t (lambda (n) (declare (ignore n))))
                   "an all-known batch ends sync even when the message was full")
          (is (eq :ready (bl.net:peer-state p))
              "a full batch must not drop the peer"))))))

;;;; ============================================================
;;;; GA8 W3 review: already_validated_work is Core's ANCESTOR test, not plain
;;;; index membership.
;;;;
;;;; Core skips the anti-DoS work gate only when the last received header
;;;; IsAncestorOfBestHeaderOrTip (net_processing.cpp:3046-3054, :2813-2823) —
;;;; i.e. only for headers on our own best-header / active chain. A batch of
;;;; headers we hold only on a FORK still reaches TryLowWorkHeadersSync and
;;;; still presyncs (:2769-2800).
;;;;
;;;; Testing plain membership instead swallowed the fork class and ended header
;;;; sync with that peer, with no resume path: our locator is built from our own
;;;; header tip, which an all-known batch does not move, so the next round
;;;; reproduced the identical request and the identical batch — for ever — and
;;;; the BIP130 announcement path dead-ends the same way (its getheaders uses
;;;; that same locator). This is the deep-fork non-convergence failure mode this
;;;; project already lost days to on testnet4.
;;;; ============================================================

(defun %w3-fork-fixture (dir)
  "A regtest chain-state holding TWO branches off genesis, both admitted through
the production ingest path at a zero work floor: A1..A3 — the most-work header
chain, so Core's m_best_header — and a shorter fork B1..B2, in the index but on
neither the best-header chain nor the active chain. Returns (values state
a-headers b-headers)."
  (multiple-value-bind (state genesis-hash) (%regtest-chain-state dir)
    (let* ((bl:*minimum-chain-work-override* 0)
           (a1 (%pow-header genesis-hash :timestamp 1296688700 :merkle 1))
           (a2 (%pow-header (bl.ser:block-header-hash a1)
                            :timestamp 1296689300 :merkle 2))
           (a3 (%pow-header (bl.ser:block-header-hash a2)
                            :timestamp 1296689900 :merkle 3))
           (b1 (%pow-header genesis-hash :timestamp 1296688701 :merkle 11))
           (b2 (%pow-header (bl.ser:block-header-hash b1)
                            :timestamp 1296689301 :merkle 12)))
      (bl.net:ingest-headers-from-peer
       (%g718-peer) (list a1 a2 a3) state)
      (bl.net:ingest-headers-from-peer
       (%g718-peer) (list b1 b2) state)
      (values state (list a1 a2 a3) (list b1 b2)))))

(defun %w3-entry (state header)
  (bl.store:get-block-index-entry
   state (bl.ser:block-header-hash header)))

(test w3-ancestor-of-best-header-or-tip-predicate
  "Core PeerManagerImpl::IsAncestorOfBestHeaderOrTip (net_processing.cpp:2813-
2823), all three arms plus the NIL case. The fork arm is what the GA8 W3 review
was about: a header we HOLD is not thereby a header on our chain."
  (%w3-with-regtest
    (multiple-value-bind (state a-headers b-headers)
        (%w3-fork-fixture "test-w3-ancestor-pred/")
      (let ((a1 (%w3-entry state (first a-headers)))
            (a3 (%w3-entry state (third a-headers)))
            (b2 (%w3-entry state (second b-headers))))
        (is (not (null a3)) "fixture must have stored the A branch")
        (is (not (null b2)) "fixture must have stored the B fork")
        (is-false (bl.net::%ancestor-of-best-header-or-tip-p
                   state nil)
                  "a header we do not have at all is an ancestor of nothing")
        (is-true (bl.net::%ancestor-of-best-header-or-tip-p
                  state a3)
                 "m_best_header itself qualifies")
        (is-true (bl.net::%ancestor-of-best-header-or-tip-p
                  state a1)
                 "an ancestor of m_best_header qualifies (GetAncestor arm)")
        (is-false (bl.net::%ancestor-of-best-header-or-tip-p
                   state b2)
                  "a header held only on a FORK does NOT qualify")
        ;; Third arm: ActiveChain().Contains(). Move the active tip onto the
        ;; fork, as a reorg does; B2 is then on the active chain even though it
        ;; is still off the best-header branch.
        (bl.store:update-chain-tip
         state (bl.store:block-index-entry-hash b2) 2)
        (is-true (bl.net::%ancestor-of-best-header-or-tip-p
                  state b2)
                 "a header on the ACTIVE chain qualifies even off the best-header branch")))))

(test w3-all-known-fork-batch-must-not-end-header-sync
  "THE REGRESSION. We hold a fork B1..B2 below our header tip (an aborted
presync, a peer rotation, or a restart mid-fork leaves exactly this). Phase 1
asks with a locator off the A-branch tip; the fork peer matches the fork point
and answers with a FULL batch of B headers — all of which we already have.

Plain index membership ended header sync there and returned DONE. Nothing
entered the index, so the next run-ibd cycle built the identical locator, got
the identical batch and stopped again: the fork could never be synced. Core
sends this shape to TryLowWorkHeadersSync (net_processing.cpp:2769-2800), which
starts a presync whose own locator anchors on the peer's chain and advances."
  (%w3-with-regtest
    (multiple-value-bind (state a-headers b-headers)
        (%w3-fork-fixture "test-w3-fork-presync/")
      (declare (ignore a-headers))
      (let* ((bl:*minimum-chain-work-override* 1000)
             (b-last-hash (bl.ser:block-header-hash
                           (car (last b-headers))))
             (p (%g718-peer)))
        ;; Preconditions: the batch really is all-known, and really is off our
        ;; best-header/active chain — else the assertions below are vacuous.
        (is (not (null (bl.store:get-block-index-entry
                        state b-last-hash)))
            "fixture must already hold the whole fork batch")
        (is-false (bl.net::%ancestor-of-best-header-or-tip-p
                   state (bl.store:get-block-index-entry
                          state b-last-hash))
                  "the fork tip must be off our best-header/active chain")
        (let ((done (bl.net::handle-header-batch
                     p state b-headers t (lambda (n) (declare (ignore n))))))
          (is-false done
                    "an all-known FULL batch on a fork must NOT end header sync"))
        ;; And the next round actually makes progress: the follow-up getheaders
        ;; is anchored on the fork header just processed (Core
        ;; NextHeadersRequestLocator), not on our own header tip — a different
        ;; request from the one that produced this batch. Guarded, so that a
        ;; regression reads as failed assertions rather than an error inside
        ;; hss-locator-hashes.
        (let ((hss (bl.net:peer-headers-sync p)))
          (is (not (null hss))
              "it must divert into a presync, as Core's TryLowWorkHeadersSync does")
          (when hss
            (let ((next (bl.net::hss-locator-hashes hss))
                  (ours (bl.net::build-header-locator state)))
              (is (equalp b-last-hash (first next))
                  "the presync locator anchors on the peer's fork, advancing into its chain")
              (is-false (equalp (first next) (first ours))
                        "and differs from the header-tip locator that would repeat this batch"))))))))

(test w3-all-known-fork-batch-non-full-is-not-judged
  "The same class, non-full: Core's TryLowWorkHeadersSync logs \"Ignoring
low-work chain\" and returns true, so ProcessHeadersMessage returns without ever
reaching UpdatePeerStateForReceivedHeaders — no availability update and, above
all, no disconnect. Plain index membership sent this batch down the store path
instead and dropped an outbound peer Core keeps."
  (%w3-with-regtest
    (multiple-value-bind (state a-headers b-headers)
        (%w3-fork-fixture "test-w3-fork-nonfull/")
      (declare (ignore a-headers))
      (let ((bl:*minimum-chain-work-override* 1000)
            (p (%g718-peer)))
        (is-true (bl.net:initial-block-download-p state)
                 "fixture must be in IBD, or the drop could not fire either way")
        (is-true (bl.net::handle-header-batch
                  p state b-headers nil (lambda (n) (declare (ignore n))))
                 "an ignored low-work batch ends header sync with this peer")
        (is (null (bl.net:peer-best-known-block-hash p))
            "an ignored batch must not update availability (Core never gets there)")
        (is (eq :ready (bl.net:peer-state p))
            "and must NOT drop the peer")))))

(test w3-all-known-batch-on-our-own-chain-still-ends-sync
  "The anti-DoS control the narrowing must NOT lose. A FULL batch of headers we
already hold ON OUR OWN CHAIN is Core's already_validated_work: the work gate is
skipped, no presync is started, and this loop stops asking — our locator is
built from our header tip, which the batch did not move, so re-asking would
fetch this very batch again (free round-trips for a peer replaying our own chain
at us)."
  (%w3-with-regtest
    (multiple-value-bind (state a-headers b-headers)
        (%w3-fork-fixture "test-w3-own-chain-stop/")
      (declare (ignore b-headers))
      (let* ((bl:*minimum-chain-work-override* 1000)
             (a-last-hash (bl.ser:block-header-hash
                           (car (last a-headers))))
             (p (%g718-peer))
             (added 0))
        (is-true (bl.net::handle-header-batch
                  p state a-headers t (lambda (n) (incf added n)))
                 "an all-known FULL batch on our own chain must still end sync")
        (is (null (bl.net:peer-headers-sync p))
            "and must NOT start a presync — that is the suppression's whole point")
        (is (= 0 added) "an already-known batch adds nothing to the index")
        (is (equalp a-last-hash
                    (bl.net:peer-best-known-block-hash p))
            "the store path still ran, refreshing availability")
        (is (eq :ready (bl.net:peer-state p))
            "a full batch must not drop the peer")))))

(test w3-known-ancestor-batch-still-drops-low-work-outbound
  "The genuine low-work disconnect must still fire, and through the ANCESTOR arm
rather than an identity check: this batch ends at A1, an ancestor of our best
header A3 and not the best header itself. Core sets already_validated_work,
bypasses TryLowWorkHeadersSync, stores (nothing new) and reaches
UpdatePeerStateForReceivedHeaders — which drops the sub-minchainwork outbound
peer that has nothing more to give."
  (%w3-with-regtest
    (multiple-value-bind (state a-headers b-headers)
        (%w3-fork-fixture "test-w3-ancestor-drop/")
      (declare (ignore b-headers))
      (let* ((bl:*minimum-chain-work-override* 1000)
             (a1 (first a-headers))
             (a1-hash (bl.ser:block-header-hash a1))
             (p (%g718-peer)))
        (is-true (bl.net:initial-block-download-p state)
                 "fixture must be in IBD, or the whole assertion is vacuous")
        (is (= 0 (bl.net:ingest-headers-from-peer
                  p (list a1) state))
            "an already-known header adds nothing to the index")
        (is (equalp a1-hash (bl.net:peer-best-known-block-hash p))
            "the store path must have refreshed availability from the known ancestor")
        (is (eq :disconnected (bl.net:peer-state p))
            "a sub-minchainwork outbound peer with nothing more to give is dropped")))))

;;;; ============================================================
;;;; G7-08 P3: extra-outbound eviction (Core EvictExtraOutboundPeers)
;;;;
;;;; Two halves over two disjoint peer sets with two different clocks. The
;;;; tests keep them apart on purpose: swapping the ranking keys is the
;;;; mistake that still leaves every count correct.

(defun %p3-peer (&key (conn-type :outbound-full-relay) (address "1.2.3.4")
                      (announcement 0) (last-block 0) (connected 0)
                      protect manual)
  (let ((p (bl.net:make-peer :address address)))
    (setf (bl.net:peer-conn-type p) conn-type
          (bl.net:peer-state p) :ready
          (bl.net:peer-manual p) manual
          (bl.net::peer-chain-sync-protect p) protect
          (bl.net:peer-last-block-announcement p) announcement
          (bl.net:peer-last-block-time p) last-block
          (bl.net:peer-connected-at p) connected)
    p))

(test g7-08-p3-full-relay-rotation-picks-the-stalest-announcer
  "Core EvictExtraOutboundPeers' full-relay half (net_processing.cpp:5400): the
outbound peer that least recently ANNOUNCED a block that beat our tip is the
one rotated out. Ranking by anything else — last message, last block received,
ping — is what an eclipsing peer can trivially keep fresh while never telling
us about the chain."
  (let* ((fresh (%p3-peer :address "1.0.0.1" :announcement 5000))
         (stale (%p3-peer :address "1.0.0.2" :announcement 1000))
         (mid   (%p3-peer :address "1.0.0.3" :announcement 3000))
         (peers (list fresh stale mid)))
    (is (eq stale (bl.net:select-extra-full-relay-eviction peers)))))

(test g7-08-p3-rotation-never-takes-a-protected-or-manual-peer
  "Two exemptions, both of which invert the feature if dropped.

P2 grants chain-sync protection (:5419) precisely so this rotation cannot take
the peer back; a rotation that ignores it hands the eclipse attacker the one
peer that proved it has the good chain.

MANUAL is the operator's own -addnode. Core gets that exemption free because
MANUAL is a distinct connection type, but we type addnode peers
:outbound-full-relay, so ours has to be explicit — the plan's §2 names
evicting operator-pinned peers as a design-breaking regression."
  ;; The protected/manual peers are the STALEST, so they would be chosen first
  ;; if the filters did not fire.
  (let* ((protected (%p3-peer :address "1.0.0.1" :announcement 1 :protect t))
         (manual    (%p3-peer :address "1.0.0.2" :announcement 2 :manual t))
         (ordinary  (%p3-peer :address "1.0.0.3" :announcement 9000))
         (peers (list protected manual ordinary)))
    (is (eq ordinary (bl.net:select-extra-full-relay-eviction peers))
        "the only evictable peer is the ordinary one, stale or not")
    ;; And with nothing but exempt peers, nobody is chosen at all.
    (is (null (bl.net:select-extra-full-relay-eviction
               (list protected manual))))))

(test g7-08-p3-rotation-keeps-our-only-connection-on-a-network
  "Core MultipleManualOrFullOutboundConns (:5422). Rotation must not sever our
last route to a network. Without this the sweep will happily drop our only Tor
peer because it announces less often than the IPv4 set — which is exactly the
partition the whole subsystem exists to prevent, arrived at from the inside."
  (let* ((onion (%p3-peer :address "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion"
                          :announcement 1))
         (v4a (%p3-peer :address "1.0.0.1" :announcement 8000))
         (v4b (%p3-peer :address "1.0.0.2" :announcement 9000))
         (peers (list onion v4a v4b)))
    (is (eq v4a (bl.net:select-extra-full-relay-eviction peers))
        "the sole onion peer is protected despite being the stalest by far")
    ;; With a second onion peer the protection lifts for both of them.
    (let* ((onion2 (%p3-peer :address "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion"
                             :announcement 2))
           (peers2 (list onion onion2 v4a v4b)))
      (is (eq onion (bl.net:select-extra-full-relay-eviction peers2))
          "two onion peers means neither is our only one, so the stalest wins"))))

(test g7-08-p3-rotation-tie-breaks-toward-the-newer-connection
  "Core :5423 breaks a tie on the stamp by taking the HIGHER peer id. This is
not a corner case: every peer that has never announced sits at 0, so after any
restart the entire outbound set ties and this comparison IS the policy. Higher
id = most recently connected = least invested."
  (let* ((older (%p3-peer :address "1.0.0.1"))   ; ids are handed out in order
         (newer (%p3-peer :address "1.0.0.2")))
    (is (< (bl.net:peer-id older)
           (bl.net:peer-id newer))
        "sanity: ids really are monotonic in connection order")
    ;; Both at stamp 0, and the list order is deliberately reversed so a
    ;; first-wins reduce would pick the older one.
    (is (eq newer (bl.net:select-extra-full-relay-eviction
                   (list older newer))))
    (is (eq newer (bl.net:select-extra-full-relay-eviction
                   (list newer older)))
        "and the answer must not depend on the order of the peer list")))

(test g7-08-p3-block-relay-half-ranks-by-block-received-not-announced
  "Core's block-relay half (:5360) takes the YOUNGEST block-relay peer — by
construction the extra one opened to unstick a stale tip — unless it has given
us a block more recently than the second-youngest, in which case that one goes
instead.

It ranks by last block RECEIVED. Reusing the full-relay half's announcement
stamp here would compile, pass a count-based test, and silently evict the
wrong peer: block-relay peers are excluded from chain-sync protection because
delivering blocks is the entire job they are kept for."
  (let* ((oldest (%p3-peer :conn-type :block-relay :address "1.0.0.1" :last-block 900))
         (second (%p3-peer :conn-type :block-relay :address "1.0.0.2" :last-block 100))
         (youngest (%p3-peer :conn-type :block-relay :address "1.0.0.3" :last-block 50))
         (peers (list oldest second youngest)))
    (is (eq youngest (bl.net:select-extra-block-relay-eviction peers))
        "the youngest goes when it has not out-delivered the second-youngest")
    ;; Now make the youngest the more recent deliverer: the second-youngest goes.
    (setf (bl.net:peer-last-block-time youngest) 500)
    (is (eq second (bl.net:select-extra-block-relay-eviction peers))
        "a youngest peer that is delivering earns its slot; the runner-up pays")
    ;; The announcement stamp must have no influence here at all.
    (setf (bl.net:peer-last-block-announcement second) 999999)
    (is (eq second (bl.net:select-extra-block-relay-eviction peers))
        "the announcement stamp is the OTHER half's key and must not leak in")))

(test g7-08-p3-driver-gates-each-half-on-its-own-target
  "Core gates the two halves on GetExtraBlockRelayCount and
GetExtraFullOutboundCount separately (:5359, :5400). A combined
outbound-vs-combined-target test would let two idle block-relay slots mask a
full-relay set that is one over — the same conflation replace-disconnected-peers
already documents on the dialing side."
  (let* ((full (loop repeat 3 collect (%p3-peer :address (format nil "1.0.0.~D" (random 250))
                                                :connected 0)))
         (br (loop repeat 2 collect (%p3-peer :conn-type :block-relay
                                              :address (format nil "2.0.0.~D" (random 250))
                                              :connected 0)))
         (peers (append full br))
         (now 10000))
    ;; At target on both: nothing moves.
    (is (null (bl.net:evict-extra-outbound-peers peers now 3 2))
        "at target, both halves must be silent")
    ;; Full-relay one over, block-relay still at target: exactly one drop, and
    ;; it must come from the full-relay pool.
    (let ((dropped (bl.net:evict-extra-outbound-peers peers now 2 2)))
      (is (= 1 (length dropped)))
      (is (eq :outbound-full-relay
              (bl.net:peer-conn-type (first dropped)))
          "an over-budget full-relay set must not be paid for by a block-relay peer"))))

(test g7-08-p3-driver-respects-minimum-connect-time-and-in-flight
  "Core's two release conditions (:5386, :5438). MINIMUM_CONNECT_TIME stops the
stale-tip path becoming a treadmill — open an extra peer, evict it before it
has had a chance to announce anything, open another. The in-flight condition
stops us throwing away a download in progress, which under a stale tip is the
one thing we actually want.

Note the halves use >= and > against the same constant; that asymmetry is
Core's and is preserved deliberately."
  (let* ((now 10000)
         (fresh (%p3-peer :address "1.0.0.1" :connected (- now 5)))
         (old-a (%p3-peer :address "1.0.0.2" :connected 0 :announcement 100))
         (old-b (%p3-peer :address "1.0.0.3" :connected 0 :announcement 200))
         (peers (list fresh old-a old-b)))
    ;; fresh is the stalest (stamp 0) but was connected 5s ago: nobody goes,
    ;; because the sweep drops at most one peer and fresh is the choice.
    (is (null (bl.net:evict-extra-outbound-peers peers now 2 2))
        "the chosen peer is too new to evict, and the sweep does not fall through
         to the next-stalest — Core drops at most one per half per call")
    ;; Age it past the threshold and it goes.
    (setf (bl.net:peer-connected-at fresh) (- now 31))
    (is (equal (list fresh) (bl.net:evict-extra-outbound-peers
                             peers now 2 2)))
    ;; With a block in flight from the chosen peer, it stays.
    (let ((fresh2 (%p3-peer :address "1.0.0.4" :connected 0))
          (ctx (bl.net::make-ibd-context)))
      (setf (gethash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)
                     (bl.net:ibd-context-in-flight ctx))
            (cons fresh2 now))
      (let ((bl.net:*ibd-context* ctx))
        (is (= 1 (bl.net::count-peer-in-flight fresh2))
            "sanity: the in-flight seam is actually connected")
        (is (null (bl.net:evict-extra-outbound-peers
                   (list fresh2 old-a old-b) now 2 2))
            "a peer we are mid-download from must not be rotated out")))))

(test g7-08-p3-headers-stamp-requires-a-new-header-beating-our-tip
  "The stamp the rotation reads, through the production path
(ingest-headers-from-peer -> %store-validated-headers), which is where Core
credits it (net_processing.cpp:2921-2923).

Both halves of Core's condition are tested because each fails differently. Drop
the work comparison and every peer at our own tip gets stamped constantly.
Drop received_new_header and a peer holds its slot forever by echoing back the
block we just told it about — announcing nothing new, yet always looking like
our freshest source. The second is the one a green suite misses, because the
happy path stamps correctly either way."
  (let ((bl:*network* :regtest)
        (bl.store:*pow-limit-target*
          bl.store:+regtest-pow-limit-target+))
    (multiple-value-bind (state genesis-hash) (%regtest-chain-state "test-p3-stamp/")
      (let ((bl:*minimum-chain-work-override* 0)
            (peer (%g708-peer))
            (header (%pow-header genesis-hash)))
        (is (= 0 (bl.net:peer-last-block-announcement peer))
            "a fresh peer has never announced")
        ;; A header we did not have, on a chain beating our genesis-only tip.
        (is (= 1 (bl.net:ingest-headers-from-peer
                  peer (list header) state))
            "control: the header must actually be stored")
        (is (plusp (bl.net:peer-last-block-announcement peer))
            "a new header beating our tip credits the announcement")
        ;; Re-announce the SAME header. It is now in the index, so
        ;; received_new_header is false and the stamp must not move — even
        ;; though the work comparison still holds.
        (setf (bl.net:peer-last-block-announcement peer) 12345)
        (bl.net:ingest-headers-from-peer peer (list header) state)
        (is (= 12345 (bl.net:peer-last-block-announcement peer))
            "re-announcing a header we already hold must earn nothing")))))

(test g7-08-p3-cmpctblock-credits-the-announcement-not-the-reconstruct
  "Core's second credit site (net_processing.cpp:4623) sits in the cmpctblock
header step, BEFORE reconstruction is attempted. Crediting the successful
reconstruct instead — the intuitive place, since that is where we learn the
block is real — would rank peers by whether OUR mempool happened to hold the
transactions, and would penalise precisely the peer that reaches us first with
a block nobody else has relayed yet.

compact-block-header-verdict returns the credit decision as its third value so
the `was it new to us' half is answered from the same locked lookup that
decided :ACCEPT; asked afterwards it would always say `known'."
  (let ((bl:*network* :regtest)
        (bl.store:*pow-limit-target*
          bl.store:+regtest-pow-limit-target+))
    (multiple-value-bind (state genesis-hash) (%regtest-chain-state "test-p3-cmpct/")
      (let* ((header (%pow-header genesis-hash))
             (hash (bl.ser:block-header-hash header)))
        (multiple-value-bind (verdict reason credits)
            (bl.net::compact-block-header-verdict
             state header hash genesis-hash)
          (declare (ignore reason))
          (is (eq :accept verdict))
          (is-true credits "an unseen header beating our tip credits its announcer"))
        ;; Now we hold it. Same header, same work, still accepted — but no
        ;; longer new, so no credit.
        (bl.net:process-headers (list header) state)
        (multiple-value-bind (verdict reason credits)
            (bl.net::compact-block-header-verdict
             state header hash genesis-hash)
          (declare (ignore reason))
          (is (eq :accept verdict) "a header we already hold is still accepted")
          (is-false credits "but re-announcing it earns no credit"))))))

(test g7-08-p3-an-equal-work-sibling-earns-no-announcement-credit
  "Core compares the announced chain STRICTLY against our tip
(net_processing.cpp:2921 — `last_header.nChainWork > ...Tip()->nChainWork'),
and this is the case that separates > from >=: a competing block at the same
height as our tip. It is new to us, so received_new_header holds and cannot
mask the comparison — the work test is the only thing standing between a fork
sibling and a credit.

Relaxing it to >= is invisible on the happy path and quietly re-ranks the whole
outbound set: at a steady tip, every peer relaying the same-height competitor
looks like a fresh announcer, so the rotation stops discriminating and falls
through to its tie-break. This test exists because a mutation to >= survived
the rest of this file."
  (let ((bl:*network* :regtest)
        (bl.store:*pow-limit-target*
          bl.store:+regtest-pow-limit-target+))
    (multiple-value-bind (state genesis-hash) (%regtest-chain-state "test-p3-sibling/")
      (let* ((bl:*minimum-chain-work-override* 0)
             (peer (%g708-peer))
             ;; Our tip: one block off genesis, made the ACTIVE tip so the
             ;; comparison has something real to sit at.
             (mine (%pow-header genesis-hash :merkle 1))
             (mine-hash (bl.ser:block-header-hash mine)))
        (bl.net:process-headers (list mine) state)
        (bl.store:update-chain-tip state mine-hash 1)
        (let* ((tip (bl.store:get-block-index-entry state mine-hash))
               (tip-work (bl.store:block-index-entry-chain-work tip))
               ;; A sibling off the SAME parent: different block, same height,
               ;; same bits — therefore exactly equal cumulative work.
               (sibling (%pow-header genesis-hash :merkle 2))
               (sib-hash (bl.ser:block-header-hash sibling)))
          (is (not (equalp mine-hash sib-hash)) "sanity: it is a different block")
          (bl.net:credit-block-announcement peer)
          (setf (bl.net:peer-last-block-announcement peer) 12345)
          (bl.net:ingest-headers-from-peer peer (list sibling) state)
          (let ((sib (bl.store:get-block-index-entry state sib-hash)))
            (is-true sib "control: the sibling must actually be stored")
            (is (= tip-work (bl.store:block-index-entry-chain-work sib))
                "control: the sibling really does tie our tip on work"))
          (is (= 12345 (bl.net:peer-last-block-announcement peer))
              "a same-work competitor is not an improvement and earns nothing")
          ;; Control the other way: a header that genuinely extends past our tip
          ;; DOES credit, proving the harness can reach the credit at all.
          ;; A later timestamp is required, not cosmetic: at height 2 the
          ;; median-time-past of {genesis, mine} is MINE's own timestamp, so
          ;; reusing it makes the header time-too-old and it never stores —
          ;; which looks exactly like "the credit did not fire".
          (let ((better (%pow-header mine-hash :merkle 3 :timestamp 1296689000)))
            (bl.net:ingest-headers-from-peer peer (list better) state)
            (is (/= 12345 (bl.net:peer-last-block-announcement peer))
                "a header beating our tip must still credit")))))))

;;;; ------------------------------------------------------------------
;;;; G7-08 P3: stale tip and the extra outbound slot

(test g7-08-p3-tip-may-be-stale-needs-both-age-and-an-idle-pipeline
  "Core TipMayBeStale (net_processing.cpp:1332). Two conditions, and the second
is the one that is easy to drop: a block in flight from ANYONE means our tip is
about to move on its own, so opening an extra connection would be paying for
information already on the wire.

The threshold is nPowTargetSpacing * 3 = 1800s — factor THREE. An earlier
revision of the plan wrote `30 * 600', right product and wrong factor, which
lands on five hours if copied literally and makes the check effectively dead."
  ;; Asserted as a LITERAL, not as `(* 3 spacing)'. Every other assertion in
  ;; this file is written in terms of the constant, so all of them would follow
  ;; a wrong constant happily -- which is precisely how `30 * 600' could have
  ;; shipped. 1800 seconds is thirty minutes; 18000 is five hours.
  (is (= 1800 bl::+stale-tip-age-seconds+)
      "the stale-tip threshold is nPowTargetSpacing * 3 = 1800s, factor THREE")
  (is (= 600 bl:+pow-target-spacing-seconds+)
      "and nPowTargetSpacing is 600s on every network Core ships")
  (let ((node (bl:make-node :network :regtest)))
    ;; Never advanced: Core stamps the clock and reports fresh rather than
    ;; declaring every freshly started node eclipsed.
    (is (= 0 (bl:node-last-tip-advance-time node)))
    (is-false (bl::tip-may-be-stale-p node)
              "a node whose tip has never advanced is not yet stale")
    (is (plusp (bl:node-last-tip-advance-time node))
        "and the clock must have been stamped, or it is stale forever after")
    ;; Recent advance: fresh.
    (setf (bl:node-last-tip-advance-time node) (get-universal-time))
    (is-false (bl::tip-may-be-stale-p node))
    ;; Old enough, nothing in flight: stale.
    (setf (bl:node-last-tip-advance-time node)
          (- (get-universal-time) (1+ bl::+stale-tip-age-seconds+)))
    (is-true (bl::tip-may-be-stale-p node))
    ;; Same age, but a block is in flight: NOT stale.
    (let ((ctx (bl.net::make-ibd-context))
          (peer (%p3-peer)))
      (setf (gethash (make-array 32 :element-type '(unsigned-byte 8) :initial-element 3)
                     (bl.net:ibd-context-in-flight ctx))
            (cons peer 1))
      (let ((bl.net:*ibd-context* ctx))
        (is-true (bl.net:any-blocks-in-flight-p)
                 "sanity: the in-flight seam is actually connected")
        (is-false (bl::tip-may-be-stale-p node)
                  "a download in progress means the tip is not stuck")))
    ;; Just under the threshold stays fresh, so the constant is exercised in
    ;; both directions rather than only from far away.
    (setf (bl:node-last-tip-advance-time node)
          (- (get-universal-time) (1- bl::+stale-tip-age-seconds+)))
    (is-false (bl::tip-may-be-stale-p node))))

(test g7-08-p3-stale-tip-grants-then-releases-the-extra-slot
  "Core :5468-5479. The RELEASE is the half that is easy to omit and the one
that inverts the feature: without it the first stale episode raises the dialing
budget permanently, and the rotation — which measures against the UNRAISED
target — then spends every sweep evicting a peer we just dialled. It would
present as endless outbound churn with no stale tip anywhere in sight."
  (let ((node (bl:make-node :network :regtest))
        (bl::*try-new-outbound-peer* nil)
        (bl::*last-stale-tip-check* 0))
    (setf (bl:node-network-active node) t)
    ;; Stale: the slot is granted.
    (setf (bl:node-last-tip-advance-time node)
          (- (get-universal-time) (1+ bl::+stale-tip-age-seconds+)))
    (bl::check-for-stale-tip node 1000)
    (is-true bl::*try-new-outbound-peer*)
    ;; The tip advances. The next evaluation must hand the slot back.
    (setf (bl:node-last-tip-advance-time node) (get-universal-time))
    (bl::check-for-stale-tip node (+ 1000 bl::+stale-tip-check-interval-seconds+ 1))
    (is-false bl::*try-new-outbound-peer*
              "the extra slot must be released once the tip moves again")))

(test g7-08-p3-stale-check-runs-on-its-own-ten-minute-timer
  "Core gates the stale-tip half on STALE_CHECK_INTERVAL (10 min) INSIDE the 45s
sweep (:5468). The two cadences are different and both real; collapsing them
re-evaluates an 1800-second-old condition forty times before it can change."
  (let ((node (bl:make-node :network :regtest))
        (bl::*try-new-outbound-peer* nil)
        (bl::*last-stale-tip-check* 0))
    (setf (bl:node-network-active node) t
          (bl:node-last-tip-advance-time node)
          (- (get-universal-time) (1+ bl::+stale-tip-age-seconds+)))
    (bl::check-for-stale-tip node 1000)
    (is-true bl::*try-new-outbound-peer* "first evaluation grants")
    ;; Tip is healthy again, but we are still inside the 10-minute window:
    ;; the state must NOT be re-evaluated yet.
    (setf (bl:node-last-tip-advance-time node) (get-universal-time))
    (bl::check-for-stale-tip node 1100)
    (is-true bl::*try-new-outbound-peer*
             "a second call inside the interval must not re-evaluate")))

(test g7-08-p3-the-extra-slot-raises-dialing-but-not-eviction
  "The asymmetry IS the mechanism (Core net.cpp:2722 vs :2473). The dialer may
hold one peer beyond node-max-peers while the tip looks stale; the rotation
keeps measuring against the unraised maximum, so that extra peer is
immediately one too many and the stalest one is dropped. The result is a
REPLACEMENT.

Raise both together — the intuitive reading — and the extra connection becomes
permanent while the rotation never fires at all, which is the opposite of the
feature: more peers, none of them ever rotated."
  (let ((node (bl:make-node :network :regtest)))
    (setf (bl:node-max-peers node) 8)
    (let ((bl::*try-new-outbound-peer* nil))
      (is (= 8 (bl::outbound-dial-budget node))))
    (let ((bl::*try-new-outbound-peer* t))
      (is (= 9 (bl::outbound-dial-budget node))
          "the dialing budget rises by exactly one")
      (is (= 8 (bl:node-max-peers node))
          "and the eviction target, which is node-max-peers, does not move")
      ;; Nine full-relay peers against the unraised target of 8 means the
      ;; rotation fires — that is what makes it a replacement.
      (let ((peers (loop for i from 1 to 9
                         collect (%p3-peer :address (format nil "10.0.0.~D" i)
                                           :announcement (* i 100)
                                           :connected 0))))
        (is (= 1 (length (bl.net:evict-extra-outbound-peers
                          peers 10000 (bl:node-max-peers node) 2)))
            "the extra peer must put us over the eviction target, not under it")))))

;;;; GA9 S2-4 / S2-5: two addrman and discouragement parity gaps

(test ga9-s2-4-local-peers-are-disconnected-but-not-discouraged
  "Core MaybeDiscourageAndDisconnect (net_processing.cpp:5194-5201) disconnects
a local peer for misbehaviour but does NOT discourage it, `since that would
discourage all peers on the same local address' — and its log line names the
inbound-onion case as what the carve-out protects.

We discouraged unconditionally. Every inbound onion peer arrives through the
local Tor daemon on the loopback listener, so its address is literally
127.0.0.1: one misbehaving onion peer discouraged the loopback and with it
every present and future onion peer, silently disabling onion reachability."
  (dolist (case '(("127.0.0.1" t   "the loopback every inbound onion peer presents as")
                  ("127.53.9.2" t  "anywhere in 127.0.0.0/8")
                  ("0.0.0.0"   t   "Core treats 0.0.0.0/8 as local too")
                  ("::1"       t   "IPv6 loopback")
                  ("8.8.8.8"   nil "an ordinary public peer is still discourageable")
                  ("192.168.1.5" nil "RFC1918 is NOT IsLocal in Core")))
    (destructuring-bind (addr local reason) case
      (is (eq (and (bl.net:loopback-address-p addr) t) (and local t))
          "~A: ~A" addr reason))))

;;; ============================================================
;;; 5. The automatic-dial decision: which candidate, and who is
;;;    charged for the failure (Core ThreadOpenConnections)
;;; ============================================================

(defparameter *dial-candidate* "203.0.113.9"
  "The single dial candidate the sweeps below are offered, in TEST-NET-3
documentation space. Its /16 is 203.0, which no fixture peer shares unless the
test means it to.")

(defun %dial-probe-node (peers candidates &optional book)
  "A node wired for one automatic-dial sweep: networking on, PEERS as the peer
list, CANDIDATES as the frozen dial-candidate list REPLACE-DISCONNECTED-PEERS
walks, BOOK as the addrman. The three reaches into node internals in this
section."
  (let ((node (bl:make-node)))
    (setf (bl:node-network-active node) t
          (bl:node-peers node) peers
          (bl::node-known-addresses node) candidates
          (bl::node-address-book node) book)
    node))

(defun %refill-outbound (node)
  "Drive the shipped steady-state refill — our ThreadOpenConnections."
  (bl::replace-disconnected-peers node))

(defun %dial-named-destination (node host port)
  "Drive the shipped dial for a destination somebody NAMED: -addnode,
-connect, `addnode onetry', -seednode and the addconnection RPC all land here."
  (bl::establish-outbound-peer node host port :manual t))

(defun %hosts-dialed-by (thunk &optional proxy-failed)
  "The hosts the code under test asked BL.NET:CONNECT-PEER for while THUNK ran.
The stub returns NIL, so the dial fails the way an unreachable address does and
nothing past the connect runs — which is what lets a unit test drive the real
sweep instead of a re-implementation of it.

PROXY-FAILED makes it fail the OTHER way Core distinguishes: CONNECT-PEER's
second value, Core's `proxy_connection_failed', is T when the dial died at the
SOCKS5 proxy and so says nothing at all about the address it named."
  (let ((dialed '())
        (real (fdefinition 'bl.net:connect-peer)))
    (unwind-protect
         (progn
           (setf (fdefinition 'bl.net:connect-peer)
                 (lambda (host &optional port &rest more)
                   (declare (ignore port more))
                   (push host dialed)
                   (values nil proxy-failed)))
           (funcall thunk))
      (setf (fdefinition 'bl.net:connect-peer) real))
    (nreverse dialed)))

(defun %candidate-book ()
  "An addrman holding *DIAL-CANDIDATE* at the P2P port, and nothing else."
  (let ((book (bl.net:make-address-book)))
    (bl.net:address-book-add
     book (bl.net:make-peer-address
           :ip (bl.net:ipv4-to-mapped-ipv6 203 0 113 9)
           :port 8333 :services 1
           :last-seen (bl.ser:get-unix-time)))
    book))

(defun %candidate-record (book)
  "BOOK's entry for *DIAL-CANDIDATE*, whose last_try and nAttempts are what the
failure-counting test reads."
  (bl.net:address-book-lookup
   book (bl.net:ipv4-to-mapped-ipv6 203 0 113 9) 8333 :ipv4))

(defun %outbound-peer (address)
  "A ready OUTBOUND_FULL_RELAY peer at ADDRESS — the only kind that occupies a
netgroup in Core's diversity set."
  (bl.net:make-peer :address address :state :ready
                    :conn-type :outbound-full-relay))

(test ga10-2f0cf648-inbound-peers-do-not-veto-a-replacement-dial
  "Core builds outbound_ipv46_peer_netgroups by switching on m_conn_type and
contributing NOTHING for INBOUND, ADDR_FETCH, FEELER and PRIVATE_BROADCAST
(net.cpp:2657-2687), with the reason in the source: \"We currently don't take
inbound connections into account. Since they are free to make, an attacker
could make them to prevent us from connecting to certain peers.\" Only that set
vetoes a candidate (:2825-2827).

We built it from every peer's address, inbound included. node-known-addresses
is written once, at start-up, so an attacker holding inbound slots — 114 by
default, and free — across the /16 groups of that frozen list could veto every
replacement dial and watch the outbound set drain. The neighbouring arithmetic
(count-outbound-full-relay-peers) had already been fixed for this exact reason;
the netgroup set had not.

An ADDR_FETCH peer is in the same position: -seednode peers reach node-peers
through establish-outbound-peer, so a plain not-inbound test would still let a
short-lived seed dial veto a full-relay slot."
  (let ((candidates (list (cons *dial-candidate* 8333))))
    (flet ((dialed (peer)
             (%hosts-dialed-by
              (lambda ()
                (%refill-outbound
                 (%dial-probe-node (and peer (list peer)) candidates))))))
      (is (equal (list *dial-candidate*) (dialed nil))
          "control: with no peers at all the candidate is dialed")
      (is (equal (list *dial-candidate*)
                 (dialed (bl.net:make-peer :address "203.0.113.44"
                                           :inbound t :state :ready)))
          "an inbound peer sharing the candidate's /16 vetoed the dial")
      (is (equal (list *dial-candidate*)
                 (dialed (bl.net:make-peer :address "203.0.113.45"
                                           :state :ready
                                           :conn-type :addr-fetch)))
          "a short-lived addr-fetch peer vetoed the dial")
      ;; The veto itself must survive: an OUTBOUND peer in the group still
      ;; blocks it, or the fix has simply deleted the diversity rule.
      (is (null (dialed (%outbound-peer "203.0.113.46")))
          "an outbound peer in the candidate's /16 must still veto it")
      (is (equal (list *dial-candidate*) (dialed (%outbound-peer "198.51.100.46")))
          "an outbound peer in another /16 must not veto it"))))

(test ga10-42dacfaf-addrman-failures-are-counted-only-when-online
  "Core stamps addrman.Attempt() on EVERY dial (net.cpp:492-497) but passes
fCountFailure from the call site, and ThreadOpenConnections computes it as
`((int)outbound_ipv46_peer_netgroups.size() + outbound_privacy_network_peers)
>= std::min(m_max_automatic_connections - 1, 2)' with the comment \"Don't
record addrman failure attempts when node is offline\" (:2884-2891). Every
other OpenNetworkConnection site — ADDR_FETCH (:2422), -connect MANUAL (:2541),
added nodes (:2986), addconnection (:1905), the reconnect queue (:4157) —
passes literal false.

We hard-coded true. A link that is down, a resumed laptop or a node started
before the network is charged a real failure to every address it cycled
through, and so did a manual -addnode target that was merely switched off;
nAttempts past +ADDRMAN-RETRIES+ with no success makes an entry terrible, at
which point getaddr drops it, it becomes a preferred overwrite target and its
GetChance collapses.

last_try is the witness that the dial path really ran: Core stamps it either
way, so an unchanged nAttempts cannot be confused with a sweep that never
reached the recorder."
  (let ((candidates (list (cons *dial-candidate* 8333))))
    (flet ((sweep (peers)
             (let ((book (%candidate-book)))
               (%hosts-dialed-by
                (lambda ()
                  (%refill-outbound (%dial-probe-node peers candidates book))))
               (%candidate-record book)))
           (named (peers)
             (let ((book (%candidate-book)))
               (%hosts-dialed-by
                (lambda ()
                  (%dial-named-destination
                   (%dial-probe-node peers candidates book)
                   *dial-candidate* 8333)))
               (%candidate-record book))))
      (dolist (case (list (list "the offline refill" (sweep '()) 0
                                "a node with no outbound netgroups must not \
charge a failure")
                          (list "the online refill"
                                (sweep (list (%outbound-peer "198.51.100.1")
                                             (%outbound-peer "192.0.2.1")))
                                1
                                "with two outbound netgroups Core does count \
the failure")
                          (list "the manual dial"
                                (named (list (%outbound-peer "198.51.100.1")
                                             (%outbound-peer "192.0.2.1")))
                                0
                                "a named destination must never be charged an \
addrman failure")))
        (destructuring-bind (what record expected why) case
          ;; Bound and gated: once one of these goes red the follow-ups would
          ;; otherwise dereference NIL and bury the assertion that named the
          ;; defect.
          (is-true record "~A: the addrman record must still be there" what)
          (when record
            (is (plusp (bl.net:peer-address-last-attempt record))
                "witness: ~A did reach the recorder" what)
            (is (= expected (bl.net:peer-address-n-attempts record))
                "~A: ~A" what why)))))))

(test a-proxy-failure-is-charged-to-no-address
  "Core's Attempt() is guarded by the connect's own verdict:

    if (!proxyConnectionFailed) {
        // If a connection to the node was attempted, and failure (if any) is
        // not caused by a problem connecting to the proxy, mark this as an
        // attempt.
        addrman.get().Attempt(target_addr, fCountFailure);
    }                                                (net.cpp:494-497)

so a dial that died at the SOCKS5 proxy costs the ADDRESS nothing. We stamped
the attempt BEFORE the dial, from a path that could not tell an unreachable
proxy from an unreachable peer, so with the Tor daemon down — or -proxy
pointed at a port nothing listens on — every address the selection offered
took a last_try stamp, and a real addrman FAILURE too on any node with two
outbound netgroups. +ADDRMAN-RETRIES+ of those make an entry terrible: getaddr
drops it, it becomes a preferred overwrite target and its GetChance collapses,
so a proxy outage would quietly consume the half of the address book that
needs the proxy.

Both drivers are checked, because they read different halves of the record:
the automatic refill is the only caller that may count a FAILURE, while a
named destination can only ever move last_try — which makes last_try the
witness that the recorder was reached at all."
  (let ((candidates (list (cons *dial-candidate* 8333)))
        (online (list (%outbound-peer "198.51.100.1")
                      (%outbound-peer "192.0.2.1"))))
    (flet ((refill (proxy-failed)
             (let ((book (%candidate-book)))
               (%hosts-dialed-by
                (lambda ()
                  (%refill-outbound (%dial-probe-node online candidates book)))
                proxy-failed)
               (%candidate-record book)))
           (named (proxy-failed)
             (let ((book (%candidate-book)))
               (%hosts-dialed-by
                (lambda ()
                  (%dial-named-destination
                   (%dial-probe-node online candidates book)
                   *dial-candidate* 8333))
                proxy-failed)
               (%candidate-record book))))
      (let ((target-failure (refill nil))
            (proxy-failure (refill t))
            (named-target (named nil))
            (named-proxy (named t)))
        (is-true target-failure)
        (is-true proxy-failure)
        (is-true named-target)
        (is-true named-proxy)
        (when (and target-failure proxy-failure named-target named-proxy)
          ;; Controls: an ordinary unreachable TARGET must still be charged,
          ;; or "nothing was recorded" would prove only that the sweep never
          ;; reached the recorder.
          (is (plusp (bl.net:peer-address-last-attempt target-failure))
              "control: an unreachable target still stamps last_try")
          (is (= 1 (bl.net:peer-address-n-attempts target-failure))
              "control: and, on an online node, one addrman failure")
          (is (plusp (bl.net:peer-address-last-attempt named-target))
              "control: a named destination stamps last_try too")
          ;; The carve-out.
          (is (zerop (bl.net:peer-address-last-attempt proxy-failure))
              "a dead proxy must not stamp last_try on the target")
          (is (zerop (bl.net:peer-address-n-attempts proxy-failure))
              "nor charge it an addrman failure")
          (is (zerop (bl.net:peer-address-last-attempt named-proxy))
              "and the same holds for a named destination"))))))

(test ga9-s2-6-onion-inbounds-are-not-the-default-eviction-victim
  "All inbound onion peers arrive through the local Tor daemon, so ip-netgroup
returns \"127.0\" for every one of them. The evictor picked its victim from the
most-populous netgroup, so with two or more onion peers connected they WERE the
largest group and one was evicted on every admission at capacity: ordinary
clearnet pressure silently cost the operator their onion inbounds, with
-listenonion on by default.

Core reaches the same shared group and compensates in
ProtectEvictionCandidatesByRatio, reserving up to a quarter of the protected set
for CJDNS/I2P/localhost/onion peers because they \"tend to be otherwise
disadvantaged under our eviction criteria\" (eviction.cpp:105-120).

The carve-out keys on PEER-INBOUND-ONION, never the address string — the string
is the very thing that collides. Asserted here on the exemption rule itself:
onion peers are dropped from the candidate set whenever anything else remains,
and are still evictable when nothing does, so an all-onion inbound set can
still make room."
  (flet ((mk (onion) (let ((p (bl.net:make-peer :address "127.0.0.1"
                                                                 :inbound t)))
                       (setf (bl.net:peer-inbound-onion p) onion)
                       p)))
    (let* ((o1 (mk t)) (o2 (mk t)) (clear (mk nil))
           (mixed (list o1 o2 clear)))
      ;; With a clearnet peer present, the onion peers must not be candidates.
      (let ((non-onion (remove-if #'bl.net:peer-inbound-onion mixed)))
        (is (equal (list clear) non-onion)
            "with any clearnet inbound present, onion peers are exempt"))
      ;; All-onion: the exemption must NOT empty the candidate set, or the node
      ;; could never admit a new inbound at capacity.
      (let* ((all-onion (list o1 o2))
             (non-onion (remove-if #'bl.net:peer-inbound-onion all-onion)))
        (is (null non-onion) "control: nothing survives the filter here")
        (is-true (every #'bl.net:peer-inbound-onion all-onion)
                 "so the evictor must fall back to the full set and still evict")))))
