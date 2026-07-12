(in-package #:bitcoin-lisp.networking)

;;; TCP Connection Management
;;;
;;; Handles low-level TCP connections to Bitcoin peers.

(defstruct connection
  "A TCP connection to a Bitcoin peer."
  (socket nil)
  (host "" :type string)
  (port 0 :type (unsigned-byte 16))
  (connected nil :type boolean)
  (last-activity 0 :type integer)
  (bytes-sent 0 :type integer)
  (bytes-received 0 :type integer)
  ;; Serializes writes to this socket: the sync thread and RPC-thread senders
  ;; (ping, getblockfrompeer) can both call send-bytes, and interleaved
  ;; write-sequence calls would corrupt the wire framing.
  (send-lock (bt:make-lock "conn-send"))
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

(defun make-tcp-connection (host port &key (timeout 10))
  "Create a TCP connection to HOST:PORT.
Returns a connection structure or NIL on failure.

When a SOCKS5 proxy is configured (*proxy*, socks5.lisp), the TCP dial goes to
the proxy instead and a SOCKS5 CONNECT tunnels to HOST:PORT — ATYP DOMAINNAME
always, so the proxy (never local DNS) resolves names. With randomized
credentials (-proxyrandomize), each connection gets fresh single-use
username/password so Tor isolates it on its own circuit. Mirrors Bitcoin
Core's ConnectThroughProxy (netbase.cpp:786-810; connect path net.cpp:439-459).
The returned connection records the TARGET host/port, so callers (including
the v1-fallback re-dial in peer.lisp) re-dial through the proxy transparently."
  (handler-case
      (let* ((proxy *proxy*)
             (socket (usocket:socket-connect (if proxy (proxy-host proxy) host)
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
      nil)))

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
  (setf (connection-socket conn) nil))

(defun connection-stream (conn)
  "Get the stream for a connection."
  (when (connection-socket conn)
    (usocket:socket-stream (connection-socket conn))))

(defun send-bytes (conn bytes)
  "Send raw bytes over the connection.
Returns the number of bytes sent or NIL on failure."
  (handler-case
      (let ((stream (connection-stream conn)))
        (when stream
          ;; One writer at a time: a whole message must hit the socket atomically.
          (bt:with-lock-held ((connection-send-lock conn))
            (write-sequence bytes stream)
            (force-output stream))
          (incf (connection-bytes-sent conn) (length bytes))
          (incf *total-bytes-sent* (length bytes))
          (setf (connection-last-activity conn) (get-universal-time))
          (length bytes)))
    (error ()
      (setf (connection-connected conn) nil)
      nil)))

(defun receive-bytes (conn count &key (timeout 30))
  "Receive exactly COUNT bytes from the connection.
Returns a byte vector or NIL on failure/timeout."
  (handler-case
      (let ((socket (connection-socket conn)))
        (when socket
          (let* ((stream (connection-stream conn))
                 (buffer (make-array count :element-type '(unsigned-byte 8)))
                 (total-read 0)
                 (deadline (+ (get-internal-real-time)
                              (* timeout internal-time-units-per-second))))
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
                       (return-from receive-bytes nil))
                     (let ((time-left (/ (- deadline (get-internal-real-time))
                                         internal-time-units-per-second)))
                       (when (<= time-left 0)
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
                         ;; Socket claims to be ready - read what we can
                         (let ((n (read-sequence buffer stream :start total-read)))
                           (when (= n total-read)
                             ;; No progress despite socket being ready - connection closed/error
                             (setf (connection-connected conn) nil)
                             (return-from receive-bytes nil))
                           (setf total-read n)))))
            (when (= total-read count)
              (incf (connection-bytes-received conn) count)
              (incf *total-bytes-received* count)
              (setf (connection-last-activity conn) (get-universal-time))
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
