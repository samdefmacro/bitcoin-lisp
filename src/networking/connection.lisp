(in-package #:bitcoin-lisp.networking)

;;; TCP Connection Management
;;;
;;; Handles low-level TCP connections to Bitcoin peers.

(defparameter +max-send-buffer-bytes+ 1000000
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
  (pushback nil :type (or null (simple-array (unsigned-byte 8) (*))))
  ;; --- Resumable receive state (Core CNode::vRecvMsg + Transport::ReceivedBytes)
  ;; A message is read across as many pump passes as it takes: whatever has
  ;; arrived is accumulated HERE and the reader returns :INCOMPLETE instead of
  ;; waiting, so no peer can hold the shared pump while its message trickles in.
  ;; RECV-BUFFER is the partially-filled vector for the read in progress and its
  ;; length is that read's byte count; NIL means no read is in progress.
  (recv-buffer nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (recv-filled 0 :type fixnum)
  ;; When a byte last actually arrived for the read in progress. The only time
  ;; the reader itself records: what counts as too long depends on who is
  ;; waiting, so the budgets live with them (receive-bytes for a blocking call,
  ;; connection-receive-expired-p for the pump).
  (recv-last-progress 0 :type integer)
  ;; Framing state for the message half-read, once its fixed-size prefix is in
  ;; and decoded: the variable-length read that follows may itself span passes,
  ;; so it has to outlive the call that produced it. v1 parks the parsed
  ;; message-header here; v2 parks the byte count its (already length-decrypted,
  ;; so unrepeatable) packet body needs. Transport-agnostic on purpose — the
  ;; reap predicate below must see "a message was begun" for either one.
  (recv-framing nil))

;;; Node-wide cumulative byte counters (survive individual connection
;;; lifetimes), for getnettotals. Bumped on every send/receive. Plain incf —
;;; a lost update under thread contention only slightly under-counts a stat,
;;; never corrupts.
(defvar *total-bytes-sent* 0
  "Total bytes written to all peer sockets since startup.")
(defvar *total-bytes-received* 0
  "Total bytes read from all peer sockets since startup.")

;;; -maxuploadtarget (Core nMaxOutboundLimit, net.h:1084 and net.cpp:3877-3941)
;;;
;;; A rolling 24-hour outbound budget. It never throttles the socket: it makes
;;; the node stop SERVING the two expensive things Core stops serving — a
;;; historical block and a whole-mempool dump — and disconnect the asker.

(defconstant +max-upload-timeframe-seconds+ 86400
  "The -maxuploadtarget cycle, 1 day (Core MAX_UPLOAD_TIMEFRAME, net.cpp:84).")

(defconstant +max-block-serialized-bytes+ 4000000
  "Core MAX_BLOCK_SERIALIZED_SIZE, the per-10-minute buffer the historical
serving limit reserves so a node under target can still relay every new block.")

(defvar *max-upload-target* 0
  "Outbound byte budget per 24h, 0 = unlimited (Core -maxuploadtarget).")

(defvar *max-outbound-cycle-start* 0
  "Unix time the current 24h cycle began, 0 before the first byte is sent.")

(defvar *max-outbound-bytes-in-cycle* 0
  "Bytes sent so far in the current cycle (Core
nMaxOutboundTotalBytesSentInCycle).")

(defun %record-outbound-cycle-bytes (n)
  "Account N sent bytes against the -maxuploadtarget cycle, rolling the cycle
when it has expired (Core CConnman::RecordBytesSent, net.cpp:3855-3872).

Counts unconditionally, even with no target set, so that turning a target on
does not start from a cycle that pretends nothing has been sent."
  (let ((now (bl.ser:get-unix-time)))
    (when (or (zerop *max-outbound-cycle-start*)
              (< (+ *max-outbound-cycle-start* +max-upload-timeframe-seconds+) now))
      (setf *max-outbound-cycle-start* now
            *max-outbound-bytes-in-cycle* 0))
    (incf *max-outbound-bytes-in-cycle* n)))

(defun max-outbound-time-left-in-cycle ()
  "Seconds left in the current cycle, 0 with no target (Core
GetMaxOutboundTimeLeftInCycle_)."
  (cond ((zerop *max-upload-target*) 0)
        ((zerop *max-outbound-cycle-start*) +max-upload-timeframe-seconds+)
        (t (max 0 (- (+ *max-outbound-cycle-start* +max-upload-timeframe-seconds+)
                     (bl.ser:get-unix-time))))))

(defun outbound-target-bytes-left ()
  "Bytes still available this cycle, 0 with no target (Core
GetOutboundTargetBytesLeft)."
  (if (zerop *max-upload-target*)
      0
      (max 0 (- *max-upload-target* *max-outbound-bytes-in-cycle*))))

(defun outbound-target-reached-p (&optional historical-block-serving-limit)
  "Whether the -maxuploadtarget budget is spent (Core OutboundTargetReached,
net.cpp:3911-3930).

HISTORICAL-BLOCK-SERVING-LIMIT reserves a buffer large enough to relay every
block once for the rest of the cycle, so serving OLD blocks stops well before
the hard limit and a node that is still following the tip can keep relaying it."
  (cond ((zerop *max-upload-target*) nil)
        (historical-block-serving-limit
         (let ((buffer (* (floor (max-outbound-time-left-in-cycle) 600)
                          +max-block-serialized-bytes+)))
           (or (>= buffer *max-upload-target*)
               (>= *max-outbound-bytes-in-cycle* (- *max-upload-target* buffer)))))
        (t (>= *max-outbound-bytes-in-cycle* *max-upload-target*))))

;;; Shutdown coordination. Set by stop-node (via request-ibd-stop) when the
;;; process is shutting down. It lives in this first-loaded networking file so
;;; the low-level socket read (receive-bytes) can poll it: without that, a TERM
;;; arriving while the sync thread is blocked in a peer read (a message wait OR a
;;; handshake) hangs until the full :timeout elapses — which is what made
;;; shutdown take minutes (the June-2026 mainnet hangs). The IBD loops (ibd.lisp)
;;; and replace-disconnected-peers (node/peers.lisp) poll it too.
(defvar *ibd-stop-requested* nil
  "T while the node is shutting down; polled by receive-bytes and the IBD/peer
loops so the sync thread exits within seconds of a TERM instead of blocking on
in-flight socket reads.")

(defun ibd-stop-requested-p ()
  "Return T if node shutdown has been requested (see *ibd-stop-requested*)."
  *ibd-stop-requested*)

;;; This flag reaches layers that cannot see networking through
;;; bl.ctx:*interrupt-check* (config.lisp), installed by node/shutdown.lisp — the
;;; only file that also sees *shutdown-request*.

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
      (bl.log:log-debug "Not dialing ~A:~D: ~A" host port refusal)
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
              (bl.log:log-debug "SOCKS5 connect to ~A:~D via ~A:~D failed: ~A"
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
                         :last-activity (bl.ser:get-node-time)))
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
      (when (socket-input-ready-p server-socket :timeout timeout)
        (let ((client (usocket:socket-accept server-socket
                                             :element-type '(unsigned-byte 8))))
          (when client
            (set-tcp-nodelay client)
            (set-socket-non-blocking client)
            (let ((host (handler-case
                            (usocket:host-to-hostname (usocket:get-peer-address client))
                          (error () "inbound")))
                  ;; The remote's EPHEMERAL source port. Recorded (it used to be
                  ;; a hardcoded 0) so an accepted peer has a real endpoint:
                  ;; getpeerinfo's `addr` needs it, and the dial-dedup guard
                  ;; compares full endpoints the way Core's m_addr_name does.
                  ;; An ephemeral source port is essentially never a peer's
                  ;; listening port, which is what keeps an inbound connection
                  ;; from blocking an outbound dial to the same host.
                  (port (or (ignore-errors (usocket:get-peer-port client)) 0)))
              (make-connection :socket client
                               :host host
                               :port port
                               :connected t
                               :last-activity (bl.ser:get-node-time))))))
    (error () nil)))

(defun close-connection (conn)
  "Close a connection."
  (when (connection-socket conn)
    (handler-case
        (usocket:socket-close (connection-socket conn))
      (error () nil)))
  (setf (connection-connected conn) nil)
  (setf (connection-socket conn) nil)
  ;; Free any buffered unsent bytes, and the partially-received message — the
  ;; latter can be up to +max-message-payload+, so a closed connection still
  ;; referenced anywhere would pin 4 MB.
  (setf (connection-send-queue-in conn) nil
        (connection-send-queue-out conn) nil
        (connection-send-queue-bytes conn) 0
        (connection-recv-buffer conn) nil
        (connection-recv-filled conn) 0
        (connection-recv-framing conn) nil))

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
  (%record-outbound-cycle-bytes n)
  (setf (connection-last-activity conn) (bl.ser:get-node-time)
        (connection-last-send-time conn) (bl.ser:get-node-time)
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

This is the whole reason the readers cannot use READ-SEQUENCE: READ-SEQUENCE
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
is dropped mid-read. 128 kbit/s is chosen to stay under plausible onion
throughput — this node treats Tor as a first-class transport.

Scope narrowed once the reader became resumable: this now bounds only the
BLOCKING reads (RECEIVE-BYTES — the handshakes), where the node really is
waiting. The pump no longer waits on anyone, so it applies
+RECEIVE-STALL-TIMEOUT-SECONDS+ instead and needs no rate floor at all — which
is Core's position, reached the way Core reaches it: by never blocking on a
peer rather than by picking a kinder number.")

(defconstant +receive-stall-timeout-seconds+ 300
  "How long a peer may deliver NOTHING toward a message it has already begun
before the pump reaps it (CONNECTION-RECEIVE-EXPIRED-P).

Generous on purpose, and the resumable reader is what makes that affordable.
While the reader blocked, a stalled peer held the whole pump, so the bound had
to be tight (a stall window plus a minimum byte rate) and every second of
slack was a second of node-wide freeze. Now a stalled peer costs one connection
slot and its partial buffer (=< +MAX-MESSAGE-PAYLOAD+) and nothing else, so the
bound only has to stop the slot leaking — Core's shape, an inactivity timeout
(20 minutes there) rather than a delivery-rate requirement.

It must also stay well ABOVE the longest pump cycle. The budget is measured
from the last byte that ARRIVED, and during IBD one cycle can be minutes of
block validation across peers; a threshold near the cycle time would reap
healthy peers whose remaining bytes are already sitting in our own receive
buffer, unread. That failure mode is why this is not the pump's :timeout.")

(defconstant +recv-reserve-ahead+ (* 256 1024)
  "How far ahead of the bytes a peer has ACTUALLY delivered the receive
accumulator may be allocated.

A message announces its own size, so allocating it up front lets a peer turn a
few bytes into megabytes of our memory held for as long as the stall budget
allows: 3 bytes of BIP324 length descriptor reserved 4 MB for 5 minutes, times
every inbound slot. The blocking reader's byte-rate floor used to cut that short
in seconds; the resumable reader deliberately has no rate floor (charging peers
for our own latency is what reaped healthy peers), so the bound has to be on the
ALLOCATION instead.

Core's number and Core's reasoning: MAX_RESERVE_AHEAD = 256 KiB, so \"attackers
that want to cause us to waste allocated memory are limited to MAX_RESERVE_AHEAD
above the largest allowed message contents size, and to MAX_RESERVE_AHEAD more
than they've actually sent us\" (net.cpp:1323-1324, 1345-1356). The buffer then
doubles as the peer earns it, so an honest large message costs O(log) copies.")

(defun %end-receive (conn)
  "Clear the read in progress. The connection is untouched — callers decide
whether it survives (see %ABANDON-RECEIVE)."
  (setf (connection-recv-buffer conn) nil
        (connection-recv-filled conn) 0
        (connection-recv-framing conn) nil)
  nil)

(defun %abandon-receive (conn)
  "Drop the read in progress and the connection with it.

THE framing rule, stated once here: bytes already consumed are gone, so the
stream can never be resynchronised — a later read would parse payload bytes as
a header, and every pass after that would eat 24 more bytes of garbage,
forever. Any failure that has eaten part of a message, plus every EOF and I/O
error (where the peer is gone anyway), must come here."
  (%end-receive conn)
  (setf (connection-connected conn) nil)
  nil)

(defun connection-receive-in-progress-p (conn)
  "T once part of a message has been CONSUMED and the rest has not arrived.

Deliberately not 'a buffer is allocated': a read that took nothing leaves the
stream on a message boundary, so it is an ordinary idle poll, not a peer to
reap or a framing hazard. Both the reap check and the give-up rule need exactly
this distinction, so they share it."
  (and (or (plusp (connection-recv-filled conn))
           (connection-recv-framing conn))
       t))

(defun %receive-gave-up (conn)
  "End a read that ran out of its caller's budget: drop the connection if part
of the message was consumed (see %ABANDON-RECEIVE), otherwise just clear the
state — timing out having taken NOTHING is the ordinary idle poll, and getting
that backwards would disconnect every quiet peer."
  (if (connection-receive-in-progress-p conn)
      (%abandon-receive conn)
      (%end-receive conn)))

(defun connection-receive-expired-p (conn)
  "T when a peer began a message and has delivered nothing toward it for
+RECEIVE-STALL-TIMEOUT-SECONDS+.

The pump must check this: a peer that sends a header and then goes silent
produces no readable data, so the drain would skip it every cycle and the
half-read message would sit there for the life of the connection. Check it
AFTER draining, never before — bytes waiting in our own receive buffer mean the
peer is not stalled at all, however long we took to get back to it."
  (and (connection-receive-in-progress-p conn)
       (> (- (get-internal-real-time) (connection-recv-last-progress conn))
          (* +receive-stall-timeout-seconds+ internal-time-units-per-second))))

(defparameter *recv-backtrace-budget* 3
  "How many non-I/O receive backtraces to log per process before falling back
to the one-line message. Bounded because this fires once per failing peer: the
2026-08-17 mainnet incident logged ~15k of these in 200k lines, and an
unbounded backtrace there would have buried the log it was meant to explain.
Three is enough — the failure repeats identically.")

(defvar *recv-backtrace-remaining* nil
  "Countdown behind *RECV-BACKTRACE-BUDGET*; NIL until the first capture.")

(defvar *recv-backtrace-lock* (bt:make-lock "recv-backtrace")
  "Guards the countdown: receive runs on the pump, the listener and the
handshake threads at once, and a lost decrement would let the budget leak.")

(defun %recv-error-diagnosable-p (c)
  "Is C one of OUR bugs rather than the peer going away? Same discrimination
the caller's log line makes, factored out so the capture and the message can
never disagree about it."
  (not (typep c '(or stream-error usocket:socket-condition end-of-file))))

(defun capture-recv-backtrace (c)
  "A backtrace for C as a string, or NIL when C is ordinary I/O or the budget
is spent.

Called from a HANDLER-BIND rather than the HANDLER-CASE below, because only
handler-bind is GUARANTEED to run before any unwinding: the standard runs its
handlers in the dynamic environment of the signal, while handler-case transfers
control first and what survives is then implementation business.

Measured here rather than assumed, since the obvious claim turns out to be too
strong: on this SBCL a handler-case handler still saw the signalling frames,
41 of them against handler-bind's 45. So handler-case is not useless — it is
merely not guaranteed, and the four frames it drops are the innermost ones,
which is precisely the end of the trace this function exists to capture."
  (when (and (%recv-error-diagnosable-p c)
             (bt:with-lock-held (*recv-backtrace-lock*)
               (let ((left (or *recv-backtrace-remaining* *recv-backtrace-budget*)))
                 (when (plusp left)
                   (setf *recv-backtrace-remaining* (1- left))
                   t))))
    ;; Never let diagnostics take the connection down: a failure to render the
    ;; backtrace must degrade to the plain message, not to a second error
    ;; inside the handler for the first one.
    (ignore-errors
     (with-output-to-string (s)
       #+sbcl (sb-debug:print-backtrace :stream s :count 40)
       #-sbcl (format s "(no backtrace: not SBCL)")))))

(defun receive-bytes-resumable (conn count)
  "Take whatever of COUNT bytes has arrived, WITHOUT waiting for the rest.

Returns the completed byte vector, :INCOMPLETE if more passes are needed, or
NIL on EOF / I/O error (the connection is dropped in that case).

This is Core's model: `Transport::ReceivedBytes` folds in whatever the socket
handed over and completed messages fall out; nothing ever blocks on a peer
(net.cpp SocketHandlerConnected -> CNode::ReceiveMsgBytes). Partial data lives
on the CONNECTION, so a 4 MiB block arriving in fragments costs this peer's turn
in the pump and nothing more.

Note what this does NOT do: time. It applies no deadline of its own, because the
right budget depends on who is waiting — the blocking wrapper bounds one call's
wait, the pump bounds peer silence (CONNECTION-RECEIVE-EXPIRED-P). Enforcing a
per-read deadline here charged peers for OUR scheduling delay, which reaped
healthy peers whenever a pump cycle ran long."
  (let ((backtrace nil))
   (handler-case
      (handler-bind ((error (lambda (c) (setf backtrace (capture-recv-backtrace c)))))
       (let ((socket (connection-socket conn))
            (stream (connection-stream conn))
            (now (get-internal-real-time)))
        (unless socket
          (return-from receive-bytes-resumable nil))
        ;; Start of a read: allocate the accumulator, but only RESERVE-AHEAD of
        ;; it (see +recv-reserve-ahead+) — the announced size is the peer's
        ;; word, not a fact.
        (unless (connection-recv-buffer conn)
          (setf (connection-recv-buffer conn)
                (make-array (min count +recv-reserve-ahead+)
                            :element-type '(unsigned-byte 8))
                (connection-recv-filled conn) 0
                (connection-recv-last-progress conn) now))
        (let ((buffer (connection-recv-buffer conn))
              (filled (connection-recv-filled conn)))
          ;; More bytes in hand than the caller now says it wants means two reads
          ;; got mixed — a framing bug here, not a peer fault.
          (when (> filled count)
            (bl.log:log-error
             "Receive state mismatch: ~D bytes in progress, asked for ~D — dropping connection"
             filled count)
            (return-from receive-bytes-resumable (%abandon-receive conn)))
          ;; Grow toward COUNT as the peer earns it.
          (when (and (= filled (length buffer)) (< filled count))
            (let ((bigger (make-array (min count
                                           (max (* 2 (length buffer))
                                                (+ filled +recv-reserve-ahead+)))
                                      :element-type '(unsigned-byte 8))))
              (replace bigger buffer :end2 filled)
              (setf buffer bigger
                    (connection-recv-buffer conn) bigger)))
          ;; Serve sniffed-ahead bytes (inbound v1/v2 detection) first.
          (let ((pushback (connection-pushback conn)))
            (when pushback
              (let ((n (min (- count filled) (length pushback))))
                (replace buffer pushback :start1 filled :end2 n)
                (incf filled n)
                (setf (connection-pushback conn)
                      (when (< n (length pushback)) (subseq pushback n))))))
          ;; Take what the socket already holds, up to what is allocated — the
          ;; next pass grows the buffer and takes more. Never waits:
          ;; drain-available-bytes is bounded by LISTEN, and we never call
          ;; wait-for-input here.
          (when (< filled count)
            (let ((n (drain-available-bytes stream buffer filled (length buffer))))
              (when (= n filled)
                ;; Nothing taken. EOF is the only reading of "readable, yet
                ;; empty" — but only after a SECOND drain comes back empty too:
                ;; LISTEN and the select below are separate syscalls, and a
                ;; segment landing between them would otherwise read as a
                ;; hangup and silently kill a healthy peer.
                (when (and (data-available-p conn)
                           (= (drain-available-bytes stream buffer filled
                                                     (length buffer))
                              filled))
                  (return-from receive-bytes-resumable (%abandon-receive conn))))
              (when (> n filled)
                (setf (connection-recv-last-progress conn) now))
              (setf filled n)))
          (setf (connection-recv-filled conn) filled)
          (cond
            ((= filled count)
             (incf (connection-bytes-received conn) count)
             (incf *total-bytes-received* count)
             ;; Read finished: clear the accumulator so the next one starts
             ;; clean. RECV-HEADER belongs to the caller's framing and is
             ;; cleared there, so %END-RECEIVE is not what we want here.
             (setf (connection-last-activity conn) (bl.ser:get-node-time)
                   (connection-last-recv-time conn) (bl.ser:get-node-time)
                   (connection-recv-buffer conn) nil
                   (connection-recv-filled conn) 0)
             buffer)
            (t :incomplete)))))
    ;; A dead socket surfaces as any of several conditions, so the net is wide —
    ;; but a wide net also swallows OUR bugs as "the peer went away". A type
    ;; error in this function once looked exactly like every peer hanging up at
    ;; once; say so instead of hiding it.
    (error (c)
      (when (%recv-error-diagnosable-p c)
        (bl.log:log-warn
         "Receive failed on ~A:~D with a non-I/O error: ~A~@[~%Backtrace:~%~A~]"
         (connection-host conn) (connection-port conn) c backtrace))
      (%abandon-receive conn)))))

(defun receive-bytes (conn count &key (timeout 30))
  "Receive exactly COUNT bytes, WAITING for them. Returns a byte vector, or NIL
on failure/timeout.

The blocking face of RECEIVE-BYTES-RESUMABLE, for the conversations that are
inherently synchronous — the version/verack handshake and the BIP324 handshake,
where nothing else can proceed until the peer answers. The shared message pump
must NOT use this: that is what let one peer's trickling message stall every
other peer (the 2026-08-11 freeze), and the resumable entry point exists to
remove exactly that.

Framing semantics are the resumable reader's; the BUDGET is this function's,
because it is the one doing the waiting. Both bounds a peer must satisfy live
here: TIMEOUT is the stall window since the last byte that actually arrived, and
+MIN-RECEIVE-BYTES-PER-SECOND+ additionally bounds the whole call, since a stall
window alone is renewable by dribbling one byte per window. The pump does not
use these — a peer that stalls it costs nothing now, so it applies the far more
generous +RECEIVE-STALL-TIMEOUT-SECONDS+ instead."
  (let ((socket (connection-socket conn))
        (deadline (+ (get-internal-real-time)
                     ;; One stall window for latency and scheduling, PLUS the
                     ;; time this read's size deserves at the floor rate. Both
                     ;; terms are needed: size alone gives a 24-byte header a
                     ;; sub-millisecond budget, TIMEOUT alone gives a 4 MiB
                     ;; block the same budget as that header.
                     (round (* (+ timeout (/ count +min-receive-bytes-per-second+))
                               internal-time-units-per-second)))))
    (unless socket
      (return-from receive-bytes nil))
    (loop
      (let ((result (receive-bytes-resumable conn count)))
        (unless (eq result :incomplete)
          ;; Completed, or failed and already abandoned.
          (return result)))
      (when (or
             ;; Bail promptly on shutdown: a blocked handshake read must not pin
             ;; the sync thread for the full budget while stop-node waits to
             ;; join it. Checked every sub-window, so abort latency is ~0.5s.
             *ibd-stop-requested*
             ;; Another thread (a send failure on the RPC ping path) may have
             ;; declared this connection dead. Without this the loop spins at
             ;; 100% CPU: wait-for-input returns ready on a dead socket, the
             ;; drain yields nothing, and data-available-p — which itself tests
             ;; connection-connected — can no longer see the EOF.
             (not (connection-connected conn))
             ;; Whole-call bound, then the stall window since the last byte.
             (> (get-internal-real-time) deadline)
             (> (- (get-internal-real-time) (connection-recv-last-progress conn))
                (* timeout internal-time-units-per-second)))
        (return (%receive-gave-up conn)))
      ;; Wait in sub-windows. A not-ready result is NOT failure: another
      ;; thread's foreign call (secp256k1) can trigger a GC safepoint whose
      ;; signal interrupts the underlying select() with EINTR, which usocket
      ;; surfaces as not-ready. Re-wait; the budget above ends genuine silence.
      (handler-case
          (socket-input-ready-p socket :timeout 0.5)
        (error () (return (%receive-gave-up conn)))))))

(defun data-available-p (conn &key (timeout 0))
  "Check if data is available to read on the connection's SOCKET.

Strictly the kernel's answer — poll(2) on the fd. It is what the EOF test in
RECEIVE-BYTES-RESUMABLE needs (\"the socket said readable, yet a drain came
back empty\"), and it is NOT the right question for \"is there another message
to process\": see CONNECTION-INPUT-PENDING-P."
  (when (and (connection-socket conn) (connection-connected conn))
    (socket-input-ready-p (connection-socket conn) :timeout timeout)))

(defun connection-input-pending-p (conn)
  "T if another message could be read from CONN right now without blocking.

The distinction from DATA-AVAILABLE-P is not academic. The readers pull bytes
with LISTEN on the Lisp STREAM (DRAIN-AVAILABLE-BYTES), and a Lisp stream
buffers: bytes the kernel handed over live in userspace, where poll(2) on the
fd cannot see them. So two messages arriving in ONE TCP segment both land in
the stream buffer, the first is read and dispatched, and a socket-only
readiness check then says \"nothing more\" — leaving the second message sitting
in a buffer we own until unrelated traffic happens to wake the socket again.

Measured: Core's sync_with_ping deliberately sends two pings back to back
(\"requires that the node calls ProcessMessage twice\"), and this node logged
ELEVEN SECONDS between processing the first and the second. Any two messages
that share a segment pay that, real peers included; it is not a test artefact.

Ordered cheapest first, and deliberately does NOT include an in-progress
partial read: a resumable receive with no bytes available must let the pump
move on, or the drain loop spins."
  (and (connection-socket conn)
       (connection-connected conn)
       (or
        ;; Sniffed-ahead bytes from inbound v1/v2 detection, not yet served.
        (and (connection-pushback conn) t)
        ;; Bytes the kernel already handed to the stream.
        (let ((stream (connection-stream conn)))
          (and stream (ignore-errors (listen stream)) t))
        ;; Bytes still in the kernel.
        (data-available-p conn))))
