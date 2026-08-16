(in-package #:bitcoin-lisp.networking)

;;; SOCKS5 outbound proxy client
;;;
;;; Byte-exact port of Bitcoin Core's Socks5() handshake (netbase.cpp:392-520)
;;; plus the Tor stream-isolation credentials generator (netbase.cpp:748-784).
;;; The CONNECT request always uses ATYP 0x03 DOMAINNAME, so destination names
;;; (and IP literals) are resolved by the proxy, never locally — the property
;;; that makes "node over Tor" leak-free and lets .onion targets work later.
;;;
;;; Loaded before connection.lisp: make-tcp-connection (the single outbound
;;; socket-connect choke point) tunnels through *proxy* when it is configured.

(defconstant +socks5-recv-timeout-seconds+ 20
  "Per-step timeout for reading a SOCKS5 handshake reply from the proxy.
Bitcoin Core g_socks5_recv_timeout = 20s (netbase.cpp:40-41).")

(defstruct proxy
  "An outbound SOCKS5 proxy (Bitcoin Core netbase.h Proxy). When
RANDOMIZE-CREDENTIALS (Core m_tor_stream_isolation, -proxyrandomize, default
on), every connection authenticates with fresh single-use credentials so Tor
puts each peer connection on its own circuit."
  (host "" :type string)
  (port 0 :type (unsigned-byte 16))
  (randomize-credentials t :type boolean))

(defvar *proxy* nil
  "The configured outbound SOCKS5 proxy (a PROXY struct), or NIL for direct
connections. Set from -proxy by apply-config-globals (config.lisp); applies to
ALL outbound P2P connections (Core init.cpp:1698-1762 sets it for every
network). When set, make-tcp-connection dials the proxy and tunnels via
SOCKS5, and discover-peers stops resolving DNS seeds locally.")

(defvar *onion-proxy* nil
  "The SOCKS5 proxy (a PROXY struct) for reaching Tor onion services, or NIL.
Set from -onion, defaulting to -proxy when unset (Core init.cpp:1764-1790).
Stored for the P1+ onion-dialing phases — nothing dials .onion yet.")

(defvar *onion-proxy-explicit* nil
  "T when the user gave -onion (any value, including -onion=0) explicitly.
The torcontrol client auto-configures the onion proxy from Tor's own
GETINFO net/listeners/socks ONLY when -onion was not given at all — Core's
gArgs.GetArg(\"-onion\", \"\") == \"\" test (torcontrol.cpp:471), which is
about the raw argument, not the derived proxy (an unadorned -proxy still
gets overridden by what Tor reports). Set by apply-config-globals.")

;;; Tor stream isolation (Core netbase.cpp:748-784
;;; TorStreamIsolationCredentialsGenerator): a per-process random 8-byte hex
;;; prefix (so separate launches never share circuits) plus a per-connection
;;; counter. username = password = "<prefix>-<n>".

(defvar *proxy-credentials-prefix* nil
  "Lazily generated per-process random prefix (16 hex chars + \"-\") for Tor
stream-isolation credentials (Core GenerateUniquePrefix, netbase.cpp:775-783).")

(defvar *proxy-credentials-counter* 0
  "Per-connection counter appended to *proxy-credentials-prefix*.")

(defvar *proxy-credentials-lock* (bt:make-lock "socks5-credentials")
  "Guards the isolation prefix/counter (outbound dials can race: sync thread
vs. RPC-triggered addnode).")

(defun next-proxy-credentials ()
  "Return the next unique stream-isolation credential string \"<prefix>-<n>\"
(used as both SOCKS5 username and password). Fresh credentials per connection
make Tor put each connection on its own circuit (Core
TorStreamIsolationCredentialsGenerator::Generate, netbase.cpp:761-767)."
  (bt:with-lock-held (*proxy-credentials-lock*)
    (unless *proxy-credentials-prefix*
      (setf *proxy-credentials-prefix*
            (concatenate 'string
                         (bitcoin-lisp.crypto:bytes-to-hex (ironclad:random-data 8))
                         "-")))
    (prog1 (format nil "~A~D" *proxy-credentials-prefix*
                   *proxy-credentials-counter*)
      (incf *proxy-credentials-counter*))))

;;; Errors

(define-condition socks5-error (error)
  ((phase :initarg :phase :reader socks5-error-phase
          :documentation "Handshake phase that failed: :greeting, :auth,
:connect, or :bind-address.")
   (message :initarg :message :reader socks5-error-message))
  (:report (lambda (condition stream)
             (format stream "SOCKS5 ~(~A~) failed: ~A"
                     (socks5-error-phase condition)
                     (socks5-error-message condition))))
  (:documentation "Signaled when the SOCKS5 proxy handshake fails."))

(defun socks5-fail (phase format-string &rest args)
  (error 'socks5-error :phase phase
                       :message (apply #'format nil format-string args)))

(defun socks5-reply-string (code)
  "Descriptive message for a SOCKS5 CONNECT reply CODE: RFC1928 codes
0x01-0x08 plus the Tor extension codes 0xF0-0xF7. Strings match Bitcoin
Core's Socks5ErrorString (netbase.cpp:352-390); code meanings are enumerated
at netbase.cpp:265-284."
  (case code
    (#x01 "general failure")
    (#x02 "connection not allowed")
    (#x03 "network unreachable")
    (#x04 "host unreachable")
    (#x05 "connection refused")
    (#x06 "TTL expired")
    (#x07 "protocol error")
    (#x08 "address type not supported")
    (#xF0 "onion service descriptor can not be found")
    (#xF1 "onion service descriptor is invalid")
    (#xF2 "onion service introduction failed")
    (#xF3 "onion service rendezvous failed")
    (#xF4 "onion service missing client authorization")
    (#xF5 "onion service wrong client authorization")
    (#xF6 "onion service invalid address")
    (#xF7 "onion service introduction timed out")
    (t (format nil "unknown (0x~2,'0X)" code))))

;;; Handshake I/O helpers

(defun %socks5-recv (socket count deadline phase)
  "Read exactly COUNT bytes from SOCKET's stream, signaling SOCKS5-ERROR if
DEADLINE (internal-time units) passes first. The wait-for-input loop mirrors
receive-bytes (connection.lisp): ≤5s sub-windows, tolerant of spurious
not-ready wakeups (EINTR under concurrent FFI), shutdown-aware. Plays the role
of Core's InterruptibleRecv under g_socks5_recv_timeout (netbase.cpp:319-350)."
  (let ((stream (usocket:socket-stream socket))
        (buffer (make-array count :element-type '(unsigned-byte 8)))
        (total 0))
    (loop while (< total count)
          ;; ibd-stop-requested-p lives in connection.lisp (loaded after this
          ;; file); the forward reference resolves at load time.
          do (when (ibd-stop-requested-p)
               (socks5-fail phase "interrupted by shutdown"))
             (let ((time-left (/ (- deadline (get-internal-real-time))
                                 internal-time-units-per-second)))
               (when (<= time-left 0)
                 (socks5-fail phase "timeout waiting for proxy reply"))
               (when (usocket:wait-for-input socket
                                             :timeout (max 0.1 (min time-left 5.0))
                                             :ready-only t)
                 ;; Take only what is available. This mirrored receive-bytes
                 ;; closely enough to inherit its defect: READ-SEQUENCE demands
                 ;; the whole remaining reply and waits inside the stream with
                 ;; no deadline, so a proxy that answers partially and then goes
                 ;; quiet pinned this thread forever — DEADLINE above could
                 ;; never be consulted again. Same fix, same reason.
                 (let ((n (handler-case (drain-available-bytes stream buffer
                                                               total count)
                            (error (e)
                              (socks5-fail phase "read error: ~A" e)))))
                   (when (or (null n) (= n total))
                     ;; Ready but no progress: proxy closed the connection.
                     (socks5-fail phase "disconnected by proxy"))
                   (setf total n)))))
    buffer))

(defun %socks5-send (socket bytes phase)
  "Write BYTES to SOCKET's stream, signaling SOCKS5-ERROR on failure."
  (handler-case
      (let ((stream (usocket:socket-stream socket)))
        (write-sequence bytes stream)
        (force-output stream))
    (error (e)
      (socks5-fail phase "send failed: ~A" e))))

(defun %string-bytes (string)
  "STRING as raw octets (char-code per char, like Core's std::string bytes)."
  (map '(simple-array (unsigned-byte 8) (*)) #'char-code string))

;;; The handshake

(defun socks5-connect (socket destination port
                       &key username password
                            (timeout +socks5-recv-timeout-seconds+))
  "Perform the SOCKS5 client handshake on the already-connected SOCKET (a
usocket), establishing a tunnel to DESTINATION:PORT. Byte-exact port of
Bitcoin Core's Socks5() (netbase.cpp:392-520):

  - greeting 05 02 00 02 when USERNAME/PASSWORD are given (NOAUTH +
    USER/PASS), else 05 01 00;
  - method 0x02 => RFC1929 sub-negotiation 01 <ulen> <user> <plen> <pass>
    expecting 01 00; method 0x00 => proceed; anything else fails;
  - CONNECT 05 01 00 03 <len> <destination> <port_hi> <port_lo> — ATYP is
    ALWAYS 0x03 DOMAINNAME so the proxy resolves names, never local DNS;
  - reply 05 <rep> 00 <atyp>: rep 0x00 succeeds, other codes map to the
    RFC1928/Tor-extension messages (socks5-reply-string); then BND.ADDR
    (per <atyp>) and BND.PORT are consumed and discarded.

Every read step is guarded by its own TIMEOUT-second deadline (Core
g_socks5_recv_timeout = 20s). Returns T on success; signals SOCKS5-ERROR on
any failure (the caller owns SOCKET and must close it then)."
  (let ((dest-bytes (%string-bytes destination))
        (auth (and username password)))
    ;; netbase.cpp:396-399: DOMAINNAME length field is one byte.
    (when (> (length dest-bytes) 255)
      (socks5-fail :connect "hostname too long: ~A" destination))
    (flet ((deadline ()
             (+ (get-internal-real-time)
                (round (* timeout internal-time-units-per-second)))))
      ;; Greeting: version + supported method identifiers (netbase.cpp:400-410).
      (%socks5-send socket
                    (if auth
                        #(#x05 #x02 #x00 #x02)  ; NOAUTH + USER/PASS
                        #(#x05 #x01 #x00))      ; NOAUTH only
                    :greeting)
      (let ((reply (%socks5-recv socket 2 (deadline) :greeting)))
        (unless (= (aref reply 0) #x05)
          (socks5-fail :greeting "proxy failed to initialize"))
        (let ((method (aref reply 1)))
          (cond
            ;; USER/PASS selected: RFC1929 sub-negotiation (netbase.cpp:422-445).
            ((and (= method #x02) auth)
             (let ((user (%string-bytes username))
                   (pass (%string-bytes password)))
               (when (or (> (length user) 255) (> (length pass) 255))
                 (socks5-fail :auth "proxy username or password too long"))
               (%socks5-send socket
                             (concatenate '(vector (unsigned-byte 8))
                                          (vector #x01 (length user)) user
                                          (vector (length pass)) pass)
                             :auth)
               (let ((auth-reply (%socks5-recv socket 2 (deadline) :auth)))
                 (unless (and (= (aref auth-reply 0) #x01)
                              (= (aref auth-reply 1) #x00))
                   (socks5-fail :auth "proxy authentication unsuccessful")))))
            ((= method #x00))               ; NOAUTH: proceed (netbase.cpp:446-447)
            (t (socks5-fail :greeting
                            "proxy requested wrong authentication method 0x~2,'0X"
                            method)))))
      ;; CONNECT request, ATYP always DOMAINNAME (netbase.cpp:451-461).
      (let ((request (make-array (+ 7 (length dest-bytes))
                                 :element-type '(unsigned-byte 8))))
        (setf (aref request 0) #x05     ; VER
              (aref request 1) #x01     ; CMD CONNECT
              (aref request 2) #x00     ; RSV
              (aref request 3) #x03     ; ATYP DOMAINNAME
              (aref request 4) (length dest-bytes))
        (replace request dest-bytes :start1 5)
        (setf (aref request (+ 5 (length dest-bytes))) (ldb (byte 8 8) port)
              (aref request (+ 6 (length dest-bytes))) (ldb (byte 8 0) port))
        (%socks5-send socket request :connect))
      ;; Reply header VER REP RSV ATYP (netbase.cpp:462-488).
      (let ((reply (%socks5-recv socket 4 (deadline) :connect)))
        (unless (= (aref reply 0) #x05)
          (socks5-fail :connect "proxy failed to accept request"))
        (unless (= (aref reply 1) #x00)
          (socks5-fail :connect "~A" (socks5-reply-string (aref reply 1))))
        (unless (= (aref reply 2) #x00)
          (socks5-fail :connect "malformed proxy response (reserved != 0)"))
        ;; Consume BND.ADDR (sized by ATYP) + 2-byte BND.PORT and discard
        ;; (netbase.cpp:489-512).
        (let ((deadline (deadline)))
          (case (aref reply 3)
            (#x01 (%socks5-recv socket 4 deadline :bind-address))
            (#x04 (%socks5-recv socket 16 deadline :bind-address))
            (#x03 (let ((len (aref (%socks5-recv socket 1 deadline :bind-address) 0)))
                    (%socks5-recv socket len deadline :bind-address)))
            (t (socks5-fail :connect "malformed proxy response (ATYP 0x~2,'0X)"
                            (aref reply 3))))
          (%socks5-recv socket 2 deadline :bind-address)))
      t)))
