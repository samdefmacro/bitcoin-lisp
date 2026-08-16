(in-package #:bitcoin-lisp.networking)

;;; TCP Connection Management
;;;
;;; Handles low-level TCP connections to Bitcoin peers.

(defconstant +max-send-buffer-bytes+ 1000000
  "Per-connection cap on buffered unsent bytes, above which the connection is
send-paused (Bitcoin Core CNode::fPauseSend; cap = -maxsendbuffer default,
1000 * DEFAULT_MAXSENDBUFFER(1000) bytes, net.h:99 / init.cpp:2105). A single
message may take the buffer past the cap (Core queues it the same way — a
>1MB block message must still be servable); while over it, send-bytes drops
further messages instead of queueing without bound.")

(defconstant +send-stall-timeout-seconds+ (* 20 60)
  "Disconnect a peer whose socket has accepted no bytes for this long while
unsent data is buffered (Bitcoin Core InactivityCheck \"socket sending
timeout\": now > m_last_send + TIMEOUT_INTERVAL, net.h TIMEOUT_INTERVAL =
20min; m_last_send advances only when the kernel accepts bytes). Core's check
runs even with an empty queue but is kept alive by periodic pings; ours is
additionally gated on data actually pending, which avoids false positives
without changing the effective behavior (a jammed socket always has data
pending — the pings themselves buffer up).")

(defstruct connection
  "A TCP connection to a Bitcoin peer."
  (socket nil)
  (host "" :type string)
  (port 0 :type (unsigned-byte 16))
  (connected nil :type boolean)
  (last-activity 0 :type integer)
  (bytes-sent 0 :type integer)
  (bytes-received 0 :type integer)
  ;; Universal-times of the last kernel-accepted write and the last completed
  ;; read (Core CNode::m_last_send / m_last_recv; 0 = never). Reported as
  ;; unix times by getpeerinfo's lastsend/lastrecv.
  (last-send-time 0 :type integer)
  (last-recv-time 0 :type integer)
  ;; Serializes writes to this socket: the sync thread and RPC-thread senders
  ;; (ping, getblockfrompeer) can both call send-bytes, and interleaved
  ;; write-sequence calls would corrupt the wire framing.
  (send-lock (bt:make-lock "conn-send"))
  ;; Per-connection outgoing send buffer (Core CNode::vSendMsg, byte-level):
  ;; whatever the kernel would not accept without blocking is queued here in
  ;; wire order and retried non-blockingly by later sends / flush passes.
  ;; Two-list FIFO (push on IN, pop off the reversed OUT) so appends and pops
  ;; are O(1). All three slots are guarded by SEND-LOCK.
  (send-queue-in nil :type list)
  (send-queue-out nil :type list)
  (send-queue-bytes 0 :type integer)
  ;; internal-real-time of the last write the kernel accepted (Core
  ;; CNode::m_last_send), for the send-stall inactivity check.
  (last-send-progress (get-internal-real-time) :type integer)
  ;; BIP324 v2 session (a v2-transport struct), or NIL for plaintext v1.
  ;; Set once by the v2 handshake; message I/O in peer.lisp branches on it.
  (transport nil)
  ;; Bytes sniffed ahead of the stream (inbound v1-vs-v2 detection reads 16
  ;; bytes before knowing which transport owns them); receive-bytes serves
  ;; these before touching the socket.
  (pushback nil :type (or null (simple-array (unsigned-byte 8) (*)))))

;;; Node-wide cumulative byte counters (survive individual connection
;;; lifetimes), for getnettotals. Bumped on every send/receive. Plain incf —
;;; a lost update under thread contention only slightly under-counts a stat,
;;; never corrupts.
(defvar *total-bytes-sent* 0
  "Total bytes written to all peer sockets since startup.")
(defvar *total-bytes-received* 0
  "Total bytes read from all peer sockets since startup.")

;;; Shutdown coordination. Set by stop-node (via request-ibd-stop) when the
;;; process is shutting down. It lives in this first-loaded networking file so
;;; the low-level socket read (receive-bytes) can poll it: without that, a TERM
;;; arriving while the sync thread is blocked in a peer read (a message wait OR a
;;; handshake) hangs until the full :timeout elapses — which is what made
;;; shutdown take minutes (the June-2026 mainnet hangs). The IBD loops (ibd.lisp)
;;; and replace-disconnected-peers (node.lisp) poll it too.
(defvar *ibd-stop-requested* nil
  "T while the node is shutting down; polled by receive-bytes and the IBD/peer
loops so the sync thread exits within seconds of a TERM instead of blocking on
in-flight socket reads.")

(defun ibd-stop-requested-p ()
  "Return T if node shutdown has been requested (see *ibd-stop-requested*)."
  *ibd-stop-requested*)

(defun join-thread-or-destroy (thread &key (timeout 5) deadline)
  "Wait for THREAD to exit, destroying it if it is still alive after TIMEOUT
seconds (or past DEADLINE, an internal-real-time absolute cutoff — pass one
shared deadline to bound the TOTAL wait when joining several threads). The
shutdown-path teardown for network threads whose blocking work was already
cancelled (socket closed, stop flag set): they exit within a poll tick or
they never will. NIL THREAD is a no-op."
  (when (and thread (bt:thread-alive-p thread))
    (let ((deadline (or deadline
                        (+ (get-internal-real-time)
                           (round (* timeout internal-time-units-per-second))))))
      (loop while (and (bt:thread-alive-p thread)
                       (< (get-internal-real-time) deadline))
            do (sleep 0.1))
      (when (bt:thread-alive-p thread)
        (bt:destroy-thread thread)))))

(defun set-tcp-nodelay (usocket-socket)
  "Disable Nagle's algorithm on USOCKET-SOCKET. Bitcoin's wire protocol
sends small request messages followed by long silence while awaiting
blocks — exactly the workload where Nagle's 200ms hold hurts throughput.
Mirrors Bitcoin Core net.cpp:1794."
  #+sbcl
  (let ((underlying (usocket:socket usocket-socket)))
    (when (typep underlying 'sb-bsd-sockets:inet-socket)
      (ignore-errors
        (setf (sb-bsd-sockets:sockopt-tcp-nodelay underlying) t))))
  #-sbcl
  (declare (ignore usocket-socket)))

(defun set-socket-non-blocking (usocket-socket)
  "Put USOCKET-SOCKET's fd in non-blocking mode (Core makes every peer socket
non-blocking, SetSocketNonBlocking / CreateSock). This is what lets the send
path (%try-send-now) write only what the kernel will accept instead of
pinning the shared sync thread on one peer's stalled TCP window. If the fcntl
fails the socket stays blocking and sends degrade to the pre-existing blocking
behavior.

It does NOT make reads safe, and this docstring used to claim otherwise —
\"SBCL fd-streams wait internally on EAGAIN, so wait-for-input + read-sequence
behave exactly as on a blocking fd\" was true, and was exactly the hazard: that
internal wait has no deadline, so one silent peer could pin the reader forever.
Bounded reading is RECEIVE-BYTES' own job, via DRAIN-AVAILABLE-BYTES."
  #+sbcl
  (let ((underlying (usocket:socket usocket-socket)))
    (when (typep underlying 'sb-bsd-sockets:socket)
      (ignore-errors
        (setf (sb-bsd-sockets:non-blocking-mode underlying) t))))
  #-sbcl
  (declare (ignore usocket-socket)))

(defun make-tcp-connection (host port &key (timeout 10))
  "Create a TCP connection to HOST:PORT.
Returns a connection structure or NIL on failure.

The proxy is picked per target network (proxy-for-target, netaddress.lisp —
a forward reference resolved at load time, like ibd-stop-requested-p in
socks5.lisp): a .onion HOST tunnels through the Tor proxy (-onion, defaulting
to -proxy), every other target through *proxy* when one is configured, else a
direct dial. A target we must not dial at all — .onion without a Tor proxy,
.b32.i2p — is refused up front with NIL, so a proxyless node never raw-dials
(and never DNS-leaks) an onion name. The SOCKS5 CONNECT uses ATYP DOMAINNAME
always, so the proxy (never local DNS) resolves names; with randomized
credentials (-proxyrandomize), each connection gets fresh single-use
username/password so Tor isolates it on its own circuit. Mirrors Bitcoin
Core's ConnectNode proxy branch (net.cpp:439-497) + ConnectThroughProxy
(netbase.cpp:786-810). The returned connection records the TARGET host/port,
so callers (including the v1-fallback re-dial in peer.lisp) re-dial through
the right proxy transparently."
  (multiple-value-bind (proxy refusal) (proxy-for-target host)
    (when refusal
      (bitcoin-lisp:log-debug "Not dialing ~A:~D: ~A" host port refusal)
      (return-from make-tcp-connection nil))
    (handler-case
      (let* ((socket (usocket:socket-connect (if proxy (proxy-host proxy) host)
                                             (if proxy (proxy-port proxy) port)
                                             :element-type '(unsigned-byte 8)
                                             :timeout timeout)))
        (set-tcp-nodelay socket)
        (when proxy
          (handler-case
              (if (proxy-randomize-credentials proxy)
                  (let ((credentials (next-proxy-credentials)))
                    (socks5-connect socket host port
                                    :username credentials :password credentials))
                  (socks5-connect socket host port))
            (error (e)
              (bitcoin-lisp:log-debug "SOCKS5 connect to ~A:~D via ~A:~D failed: ~A"
                                      host port (proxy-host proxy) (proxy-port proxy) e)
              (ignore-errors (usocket:socket-close socket))
              (return-from make-tcp-connection nil))))
        ;; Non-blocking AFTER the SOCKS5 handshake: socks5-connect speaks over
        ;; the blocking stream and needs no change in semantics.
        (set-socket-non-blocking socket)
        (make-connection :socket socket
                         :host host
                         :port port
                         :connected t
                         :last-activity (get-universal-time)))
      (usocket:socket-error (e)
        (declare (ignore e))
        nil)
      (usocket:timeout-error (e)
        (declare (ignore e))
        nil))))

(defun open-listener (bind port &key (backlog 16))
  "Open a listening TCP server socket on BIND:PORT for inbound peers. Returns the
usocket server socket, or NIL on failure (e.g. port already in use)."
  (handler-case
      (usocket:socket-listen bind port
                             :element-type '(unsigned-byte 8)
                             :reuse-address t
                             :backlog backlog)
    (error () nil)))

(defun close-listener (server-socket)
  "Close a listening server socket."
  (when server-socket
    (ignore-errors (usocket:socket-close server-socket))))

(defun accept-connection (server-socket &key (timeout 1))
  "Wait up to TIMEOUT seconds for an inbound connection on SERVER-SOCKET; on one,
accept and wrap it in a connection. Returns the connection, or NIL on timeout or
error. The timeout lets the accept loop poll a shutdown flag between waits."
  (handler-case
      (when (usocket:wait-for-input server-socket :timeout timeout :ready-only t)
        (let ((client (usocket:socket-accept server-socket
                                             :element-type '(unsigned-byte 8))))
          (when client
            (set-tcp-nodelay client)
            (set-socket-non-blocking client)
            (let ((host (handler-case
                            (usocket:host-to-hostname (usocket:get-peer-address client))
                          (error () "inbound"))))
              (make-connection :socket client
                               :host host
                               :port 0
                               :connected t
                               :last-activity (get-universal-time))))))
    (error () nil)))

(defun close-connection (conn)
  "Close a connection."
  (when (connection-socket conn)
    (handler-case
        (usocket:socket-close (connection-socket conn))
      (error () nil)))
  (setf (connection-connected conn) nil)
  (setf (connection-socket conn) nil)
  ;; Free any buffered unsent bytes.
  (setf (connection-send-queue-in conn) nil
        (connection-send-queue-out conn) nil
        (connection-send-queue-bytes conn) 0))

(defun connection-stream (conn)
  "Get the stream for a connection."
  (when (connection-socket conn)
    (usocket:socket-stream (connection-socket conn))))

;;; --- Non-blocking send path -------------------------------------------------
;;;
;;; Bitcoin Core never blocks its message thread on a peer's socket: writes go
;;; through send(MSG_DONTWAIT) on a non-blocking fd, whatever the kernel won't
;;; take sits in a per-peer queue (vSendMsg) retried from the socket loop, a
;;; peer whose queue exceeds -maxsendbuffer is send-paused (fPauseSend), and a
;;; socket that accepts nothing for TIMEOUT_INTERVAL is disconnected
;;; (net.cpp CConnman::SocketSendData / InactivityCheck). Our previous
;;; send-bytes did a blocking write-sequence on the shared sync thread — one
;;; peer advertising a zero TCP window pinned the entire node. The port below
;;; keeps Core's structure at the byte level (we buffer wire bytes, not
;;; message objects — the framing/encryption has already happened by the time
;;; send-bytes runs, including BIP324 packets whose cipher order must equal
;;; wire order): non-blocking write, per-connection FIFO of the remainder,
;;; the same 1MB pause cap, and the same 20-minute send-stall disconnect.
;;; Divergence from Core, documented in the PR: while a peer is over the cap
;;; we DROP new messages instead of pausing message processing (our handlers
;;; respond synchronously and cannot be paused); the peer's own timeout
;;; machinery (ping/pong, block-request timeouts, the stall check) then
;;; disconnects it, which is Core's eventual outcome too.

(defun %connection-sb-socket (conn)
  "The underlying sb-bsd-sockets socket of CONN, or NIL."
  #+sbcl
  (let ((sock (connection-socket conn)))
    (when sock
      (let ((raw (usocket:socket sock)))
        (and (typep raw 'sb-bsd-sockets:socket) raw))))
  #-sbcl
  (progn conn nil))

(defun %try-send-now (conn bytes)
  "Write as much of BYTES to CONN's socket as the kernel accepts without
blocking. Returns the number of bytes accepted (0 on would-block), or :ERROR
on a hard socket failure. sb-bsd-sockets:socket-send on a non-blocking fd
returns a partial count when the buffer fills mid-write and NIL on
EAGAIN/EINTR (verified on SBCL 2.5/2.6). Non-SBCL fallback: the old blocking
full write through the stream."
  #+sbcl
  (let ((raw (%connection-sb-socket conn)))
    (if raw
        (handler-case
            (or (sb-bsd-sockets:socket-send raw bytes (length bytes)) 0)
          (error () :error))
        :error))
  #-sbcl
  (handler-case
      (let ((stream (connection-stream conn)))
        (if stream
            (progn (write-sequence bytes stream)
                   (force-output stream)
                   (length bytes))
            :error))
    (error () :error)))

(defun %record-send-progress (conn n)
  "Account N bytes the kernel just accepted (Core m_last_send / nSendBytes)."
  (incf (connection-bytes-sent conn) n)
  (incf *total-bytes-sent* n)
  (setf (connection-last-activity conn) (get-universal-time)
        (connection-last-send-time conn) (get-universal-time)
        (connection-last-send-progress conn) (get-internal-real-time)))

(defun %flush-send-queue-locked (conn)
  "Write as much buffered data as the socket accepts without blocking (Core
CConnman::SocketSendData). Returns T while the connection remains usable, NIL
after a hard send failure (connection marked dead). Caller holds SEND-LOCK."
  (loop
    ;; Refill the pop side from the push side when it runs dry (FIFO).
    (when (and (null (connection-send-queue-out conn))
               (connection-send-queue-in conn))
      (setf (connection-send-queue-out conn)
            (nreverse (connection-send-queue-in conn))
            (connection-send-queue-in conn) nil))
    (let ((chunk (first (connection-send-queue-out conn))))
      (unless chunk (return t))
      (let ((n (%try-send-now conn chunk)))
        (cond
          ((eq n :error)
           (setf (connection-connected conn) nil)
           (return nil))
          ((zerop n) (return t))               ; would-block: retry later
          (t
           (%record-send-progress conn n)
           (decf (connection-send-queue-bytes conn) n)
           (if (< n (length chunk))
               ;; Partial: keep the remainder at the queue head; the socket
               ;; buffer is full, so stop (Core: "could not send full
               ;; message; stop sending more").
               (progn
                 (setf (first (connection-send-queue-out conn))
                       (subseq chunk n))
                 (return t))
               (pop (connection-send-queue-out conn)))))))))

(defun %enqueue-send-bytes (conn bytes)
  "Append BYTES to CONN's send queue (wire order). Caller holds SEND-LOCK."
  (push bytes (connection-send-queue-in conn))
  (incf (connection-send-queue-bytes conn) (length bytes)))

(defun connection-send-paused-p (conn)
  "T while CONN's buffered unsent data exceeds the send-buffer cap (Core
CNode::fPauseSend). Bulk producers (block serving in handle-getdata, exactly
where Core checks it in ProcessGetData) stop sending to a paused peer;
send-bytes drops further messages until the buffer drains below the cap."
  (> (connection-send-queue-bytes conn) +max-send-buffer-bytes+))

(defun connection-send-stalled-p (conn)
  "T when CONN has had unsent data buffered while the socket accepted nothing
for +send-stall-timeout-seconds+ (Core InactivityCheck \"socket sending
timeout\"). check-peer-health disconnects such peers."
  (and (plusp (connection-send-queue-bytes conn))
       (> (- (get-internal-real-time) (connection-last-send-progress conn))
          (* +send-stall-timeout-seconds+ internal-time-units-per-second))))

(defun flush-send-buffer (conn)
  "Retry CONN's buffered unsent bytes without blocking (the periodic half of
Core's SocketSendData, driven here from the sync/IBD housekeeping passes
since we have no dedicated socket thread). Returns T while the connection
remains usable."
  (if (plusp (connection-send-queue-bytes conn))
      (bt:with-lock-held ((connection-send-lock conn))
        (%flush-send-queue-locked conn))
      t))

(defun send-bytes (conn bytes)
  "Send raw bytes over the connection without ever blocking the calling
thread: bytes the kernel won't take immediately are queued on the connection
and retried by later sends / flush passes. Returns the number of bytes
accepted (sent or queued), or NIL when the message was dropped — connection
dead, or send-paused with the buffer over +max-send-buffer-bytes+."
  (when (zerop (length bytes))
    (return-from send-bytes 0))
  (handler-case
      ;; One writer at a time: a whole message must enter the queue/socket
      ;; atomically, and queue order must equal wire order.
      (bt:with-lock-held ((connection-send-lock conn))
        ;; Older unsent data goes first — never interleave.
        (unless (%flush-send-queue-locked conn)
          (return-from send-bytes nil))
        (cond
          ((plusp (connection-send-queue-bytes conn))
           ;; Still backed up. Queue behind it — unless over the cap, in
           ;; which case the message is dropped (see pause note above).
           (cond ((connection-send-paused-p conn) nil)
                 (t (%enqueue-send-bytes conn bytes)
                    (length bytes))))
          (t
           ;; Queue empty: optimistic direct send (Core PushMessage's
           ;; optimistic SocketSendData), buffering any remainder.
           (let ((n (%try-send-now conn bytes)))
             (cond
               ((eq n :error)
                (setf (connection-connected conn) nil)
                nil)
               (t
                (when (plusp n) (%record-send-progress conn n))
                (when (< n (length bytes))
                  (%enqueue-send-bytes conn (if (zerop n) bytes (subseq bytes n))))
                (length bytes)))))))
    (error ()
      (setf (connection-connected conn) nil)
      nil)))

(defun drain-available-bytes (stream buffer start end)
  "Copy every byte STREAM can supply right now into BUFFER[START..END), without
ever blocking. Returns the new fill pointer; a return equal to START means
nothing was available, which at EOF is how the caller learns the peer closed
(LISTEN reports false at EOF rather than signalling, so EOF and
nothing-yet-arrived are the same answer here — the caller distinguishes them by
having been told the socket was readable).

This is the whole reason RECEIVE-BYTES cannot use READ-SEQUENCE: READ-SEQUENCE
fills its whole range or hits EOF, and a socket stream that runs dry mid-range
waits internally with no deadline of its own. LISTEN answers the only question
that keeps the reader safe — is there a byte I can take without waiting — so
draining byte-by-byte is bounded by construction. It is also fast: measured at
~95 MB/s on the project container, i.e. ~40 ms for a maximum-size block, which
is noise next to that block's script validation."
  (loop while (and (< start end) (listen stream))
        do (let ((byte (read-byte stream nil nil)))
             ;; LISTEN said a byte was there; NIL would mean it vanished, which
             ;; cannot happen on a stream we alone read. Stop rather than store
             ;; a bogus value.
             (unless byte
               (return-from drain-available-bytes start))
             (setf (aref buffer start) byte)
             (incf start)))
  start)

(defconstant +min-receive-bytes-per-second+ 16384
  "Slowest average delivery RECEIVE-BYTES will sit through for one message.

A stall timeout alone is not enough. It is measured from the last byte that
arrived, so ANY progress renews it: a peer dribbling one byte just inside every
window keeps the budget alive forever at a cost of ~1 B/s. With the pump's
one-second timeout that turns a maximum-size message into roughly 43 DAYS of
holding the serial pump — an infinite hang traded for a slow-loris, which is no
fix at all. Requiring an average rate as well bounds the hold to
COUNT/+MIN-RECEIVE-BYTES-PER-SECOND+ and makes the attacker pay real bandwidth
for every second of it.

The rate is a straight trade against honest slow links, because a peer below it
is dropped mid-message. 128 kbit/s is chosen to stay under plausible onion
throughput — this node treats Tor as a first-class transport — at the cost of a
looser bound (~4 minutes for a maximum-size message, and the attacker must send
its whole 4,000,000 bytes to buy that). Core makes no such trade: it never
drops a slow-but-progressing peer, because it never blocks on one. Closing that
gap needs the resumable reader described on RECEIVE-BYTES, not a higher rate
here — raising this constant buys a tighter DoS bound by disconnecting honest
peers, which is the wrong side of the trade.")

(defun receive-bytes (conn count &key (timeout 30))
  "Receive exactly COUNT bytes from the connection.
Returns a byte vector or NIL on failure/timeout.

Two bounds apply, and a peer must satisfy both. TIMEOUT bounds STALLING: it is
measured from the last byte that actually arrived, so a slow-but-progressing
peer can keep delivering (Core's inactivity-timeout shape) while a peer that
stops mid-message is dropped. +MIN-RECEIVE-BYTES-PER-SECOND+ additionally
bounds the TOTAL, because a stall bound by itself is renewable by dribbling.

Residual limitation, unchanged by these bounds: this reader is synchronous, so
one peer still owns the shared message pump for the duration of its message.
Core avoids that entirely by accumulating partial messages per connection
(CNode::vRecvMsg) and never blocking on any peer. Making our reader resumable
the same way is the real fix; these bounds only make the worst case finite."
  (handler-case
      (let ((socket (connection-socket conn)))
        (when socket
          (let* ((stream (connection-stream conn))
                 (buffer (make-array count :element-type '(unsigned-byte 8)))
                 (total-read 0)
                 (last-progress (get-internal-real-time))
                 ;; Whole-message budget: one stall window for latency and
                 ;; scheduling, PLUS the time the message's own size deserves at
                 ;; the floor rate (see +MIN-RECEIVE-BYTES-PER-SECOND+). Both
                 ;; terms are needed — size alone gives a 24-byte header a
                 ;; sub-millisecond budget, and TIMEOUT alone gives a 4 MiB
                 ;; block the same budget as that header.
                 (hard-deadline (+ (get-internal-real-time)
                                   (* (+ timeout
                                         (/ count +min-receive-bytes-per-second+))
                                      internal-time-units-per-second))))
            ;; Serve sniffed-ahead bytes (inbound v1/v2 detection) first.
            (let ((pushback (connection-pushback conn)))
              (when pushback
                (let ((n (min count (length pushback))))
                  (replace buffer pushback :end2 n)
                  (setf total-read n
                        (connection-pushback conn)
                        (when (< n (length pushback)) (subseq pushback n))))))
            ;; Read until we have all bytes or timeout
            (loop while (< total-read count)
                  ;; Bail promptly on shutdown: a blocked peer read (message wait
                  ;; or handshake) must not pin the sync thread for the full
                  ;; :timeout while stop-node waits to join it. Checked each
                  ;; iteration (wait-for-input below is capped at 5s chunks), so
                  ;; abort latency is <=5s instead of up to :timeout.
                  do (when *ibd-stop-requested*
                       ;; Same framing rule as the timeout path below: bytes
                       ;; already consumed are dropped on the floor, so a
                       ;; partially-read message leaves the stream unusable.
                       (when (plusp total-read)
                         (setf (connection-connected conn) nil))
                       (return-from receive-bytes nil))
                     (let ((time-left
                             (min
                              ;; stall bound: since the last byte that arrived
                              (- timeout
                                 (/ (- (get-internal-real-time) last-progress)
                                    internal-time-units-per-second))
                              ;; total bound: dribbling must not renew forever
                              (/ (- hard-deadline (get-internal-real-time))
                                 internal-time-units-per-second))))
                       (when (<= time-left 0)
                         ;; Out of budget. If we already consumed part of a
                         ;; message those bytes are gone and the caller is told
                         ;; "failed", so the stream can never be resynchronized:
                         ;; a later read would parse payload bytes as a header.
                         ;; Kill the connection in that case only — a timeout
                         ;; with NOTHING consumed is the ordinary idle poll and
                         ;; must leave the peer alone.
                         (when (plusp total-read)
                           (setf (connection-connected conn) nil))
                         (return-from receive-bytes nil))
                       ;; Wait for data, but only up to a 5s sub-window at a
                       ;; time. A not-ready result is NOT treated as failure:
                       ;; another thread's foreign call (secp256k1) can trigger
                       ;; a GC safepoint whose signal interrupts the underlying
                       ;; select() with EINTR, which usocket surfaces as
                       ;; not-ready. We simply re-wait until the real deadline;
                       ;; genuine silence is caught by the time-left check above.
                       (when (usocket:wait-for-input socket
                                                     :timeout (max 0.1 (min time-left 5.0))
                                                     :ready-only t)
                         ;; Socket claims to be ready — take only what is
                         ;; actually there. READ-SEQUENCE would instead insist on
                         ;; the FULL remaining message: wait-for-input promises
                         ;; just one readable byte, so a peer that announces a
                         ;; 4 MiB payload and then goes quiet used to pin this
                         ;; thread in poll() FOREVER — and the message pump is
                         ;; serial, so that was the whole node's networking.
                         ;; Proven live: a node sat frozen for 5 days with 751
                         ;; sockets rotting in CLOSE-WAIT and not one error
                         ;; logged.
                         (let ((n (drain-available-bytes stream buffer
                                                         total-read count)))
                           (when (= n total-read)
                             ;; Readable but nothing to take: EOF, i.e. the peer
                             ;; closed. (The old code reached the same
                             ;; conclusion from read-sequence making no
                             ;; progress.)
                             (setf (connection-connected conn) nil)
                             (return-from receive-bytes nil))
                           (setf total-read n
                                 last-progress (get-internal-real-time))))))
            (when (= total-read count)
              (incf (connection-bytes-received conn) count)
              (incf *total-bytes-received* count)
              (setf (connection-last-activity conn) (get-universal-time)
                    (connection-last-recv-time conn) (get-universal-time))
              buffer))))
    (error ()
      (setf (connection-connected conn) nil)
      nil)))

(defun data-available-p (conn &key (timeout 0))
  "Check if data is available to read on the connection."
  (when (and (connection-socket conn) (connection-connected conn))
    (usocket:wait-for-input (connection-socket conn)
                            :timeout timeout
                            :ready-only t)))
