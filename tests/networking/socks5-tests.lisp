(in-package #:bitcoin-lisp.tests)

;;; SOCKS5 outbound proxy tests.
;;;
;;; Drives socks5-connect (and make-tcp-connection's proxy path) against a
;;; canned fake SOCKS5 server on loopback: a listener thread executes a byte
;;; script (read N / write bytes) while capturing everything the client sends,
;;; so the handshake can be asserted byte-exactly against Bitcoin Core's
;;; Socks5() (netbase.cpp:392-520). No live Tor, no external network.

(def-suite :socks5-tests
  :description "SOCKS5 proxy client handshake, stream isolation, -proxy config"
  :in :bitcoin-lisp-tests)

(in-suite :socks5-tests)

(defun %fake-socks5-server (script)
  "Run a one-shot scripted server on 127.0.0.1. SCRIPT is a list of steps:
 (:read N) read N bytes, (:write BYTES) send BYTES, (:sleep SECONDS) pause,
 (:read-userpass) adaptively read an RFC1929 auth message, (:read-connect)
adaptively read a SOCKS5 CONNECT request. All received bytes are captured.
Returns (values PORT THREAD CAPTURED)."
  (let* ((srv (usocket:socket-listen "127.0.0.1" 0
                                     :element-type '(unsigned-byte 8)
                                     :reuse-address t))
         (port (usocket:get-local-port srv))
         (captured (make-array 0 :element-type '(unsigned-byte 8)
                                 :adjustable t :fill-pointer t))
         (thread
           (bt:make-thread
            (lambda ()
              (unwind-protect
                  (let* ((client (usocket:socket-accept
                                  srv :element-type '(unsigned-byte 8)))
                         (stream (usocket:socket-stream client)))
                    (unwind-protect
                        (flet ((rd (n)
                                 (let ((last 0))
                                   (dotimes (i n last)
                                     (setf last (read-byte stream))
                                     (vector-push-extend last captured)))))
                          (dolist (step script)
                            (ecase (first step)
                              (:read (rd (second step)))
                              (:write (write-sequence (second step) stream)
                                      (force-output stream))
                              (:sleep (sleep (second step)))
                              (:read-userpass       ; 01 ulen user plen pass
                               (rd 1)
                               (let ((ulen (rd 1)))
                                 (rd ulen)
                                 (let ((plen (rd 1)))
                                   (rd plen))))
                              (:read-connect        ; 05 01 00 03 len name port
                               (rd 4)
                               (let ((len (rd 1)))
                                 (rd (+ len 2)))))))
                      (ignore-errors (usocket:socket-close client))))
                (ignore-errors (usocket:socket-close srv))))
            :name "fake-socks5-server")))
    (values port thread captured)))

(defmacro with-socks5-client ((socket-var port) &body body)
  "Connect a loopback client SOCKET to 127.0.0.1:PORT around BODY."
  `(let ((,socket-var (usocket:socket-connect "127.0.0.1" ,port
                                              :element-type '(unsigned-byte 8)
                                              :timeout 5)))
     (unwind-protect (progn ,@body)
       (ignore-errors (usocket:socket-close ,socket-var)))))

(defun %socks5-error-message (thunk)
  "Call THUNK; return (values message phase) of the signaled socks5-error, or
NIL if none was signaled."
  (handler-case (progn (funcall thunk) nil)
    (bl.net:socks5-error (e)
      (values (bl.net::socks5-error-message e)
              (bl.net:socks5-error-phase e)))))

;;; --- handshake success paths ------------------------------------------------

(test socks5-noauth-success-and-domainname-encoding
  "NOAUTH handshake succeeds; the wire bytes are Core's exactly: greeting
05 01 00, CONNECT with ATYP 0x03 DOMAINNAME + hostname bytes + port hi/lo
(netbase.cpp:400-461). IPv4 BND.ADDR (4 bytes) + port are consumed."
  (multiple-value-bind (port thread captured)
      (%fake-socks5-server
       ;; greeting reply: v5, NOAUTH; connect reply: success, ATYP IPv4
       `((:read 3) (:write #(#x05 #x00))
         (:read 18)                     ; 4 hdr + 1 len + 11 "example.com" + 2 port
         (:write #(#x05 #x00 #x00 #x01 10 0 0 1 #x47 #x9D))))
    (with-socks5-client (sock port)
      (is-true (bl.net:socks5-connect
                sock "example.com" 18333 :timeout 5)))
    (bt:join-thread thread)
    (is (= 21 (length captured)))
    ;; Greeting: 05 01 00 (one method, NOAUTH).
    (is (equalp #(#x05 #x01 #x00) (subseq captured 0 3)))
    ;; CONNECT: 05 01 00 03 <len> <hostname> <port_hi> <port_lo>.
    (is (equalp #(#x05 #x01 #x00 #x03 11) (subseq captured 3 8)))
    (is (equalp (map 'vector #'char-code "example.com") (subseq captured 8 19)))
    (is (= #x47 (aref captured 19)))    ; 18333 = 0x479D
    (is (= #x9D (aref captured 20)))))

(test socks5-userpass-success
  "USER/PASS handshake: greeting advertises both methods (05 02 00 02), the
RFC1929 sub-negotiation is 01 <ulen> <user> <plen> <pass>, and a DOMAINNAME
BND.ADDR is consumed cleanly (netbase.cpp:400-445, 489-505)."
  (multiple-value-bind (port thread captured)
      (%fake-socks5-server
       `((:read 4) (:write #(#x05 #x02))          ; select USER/PASS
         (:read-userpass) (:write #(#x01 #x00))   ; auth OK
         (:read-connect)
         ;; success, ATYP DOMAINNAME: len 3 "foo" + port
         (:write #(#x05 #x00 #x00 #x03 3 #x66 #x6F #x6F #x1F #x40))))
    (with-socks5-client (sock port)
      (is-true (bl.net:socks5-connect
                sock "abc.onion" 8333
                :username "user" :password "pass" :timeout 5)))
    (bt:join-thread thread)
    ;; Greeting: 05 02 00 02 (NOAUTH + USER/PASS).
    (is (equalp #(#x05 #x02 #x00 #x02) (subseq captured 0 4)))
    ;; RFC1929: 01 04 "user" 04 "pass".
    (is (equalp #(#x01 4 117 115 101 114 4 112 97 115 115)
                (subseq captured 4 15)))
    ;; CONNECT carries the destination name.
    (is (equalp (map 'vector #'char-code "abc.onion") (subseq captured 20 29)))))

(test socks5-noauth-selected-despite-credentials
  "When credentials are offered but the proxy selects NOAUTH (method 0), the
handshake proceeds without sub-negotiation (netbase.cpp:446-447). IPv6
BND.ADDR (16 bytes) is consumed cleanly."
  (multiple-value-bind (port thread captured)
      (%fake-socks5-server
       `((:read 4) (:write #(#x05 #x00))          ; select NOAUTH
         (:read-connect)
         (:write ,(concatenate '(vector (unsigned-byte 8))
                               #(#x05 #x00 #x00 #x04)
                               (make-array 16 :initial-element 0)
                               #(#x20 #x8D)))))
    (with-socks5-client (sock port)
      (is-true (bl.net:socks5-connect
                sock "10.1.2.3" 8333
                :username "u" :password "p" :timeout 5)))
    (bt:join-thread thread)
    ;; No RFC1929 bytes: the greeting is followed directly by CONNECT.
    (is (= #x05 (aref captured 4)))
    (is (= #x01 (aref captured 5)))))

;;; --- handshake failure paths ------------------------------------------------

(test socks5-rep-general-failure
  "REP 0x01 maps to Core's \"general failure\" (netbase.cpp:354-355) and
signals a socks5-error in the :connect phase."
  (multiple-value-bind (port thread)
      (%fake-socks5-server
       `((:read 3) (:write #(#x05 #x00))
         (:read 18) (:write #(#x05 #x01 #x00 #x01))))
    (with-socks5-client (sock port)
      (multiple-value-bind (message phase)
          (%socks5-error-message
           (lambda () (bl.net:socks5-connect
                       sock "example.com" 18333 :timeout 5)))
        (is (equal "general failure" message))
        (is (eq :connect phase))))
    (bt:join-thread thread)))

(test socks5-rep-tor-extension-code
  "Tor extension REP 0xF0 maps to \"onion service descriptor can not be
found\" (netbase.cpp:368-369)."
  (multiple-value-bind (port thread)
      (%fake-socks5-server
       `((:read 3) (:write #(#x05 #x00))
         (:read 16) (:write #(#x05 #xF0 #x00 #x01))))
    (with-socks5-client (sock port)
      (is (equal "onion service descriptor can not be found"
                 (%socks5-error-message
                  (lambda () (bl.net:socks5-connect
                              sock "abc.onion" 8333 :timeout 5))))))
    (bt:join-thread thread)))

(test socks5-wrong-auth-method-rejected
  "A proxy selecting an unoffered method (e.g. 0xFF no-acceptable) fails the
greeting phase (netbase.cpp:448-450)."
  (multiple-value-bind (port thread)
      (%fake-socks5-server `((:read 3) (:write #(#x05 #xFF))))
    (with-socks5-client (sock port)
      (multiple-value-bind (message phase)
          (%socks5-error-message
           (lambda () (bl.net:socks5-connect
                       sock "example.com" 18333 :timeout 5)))
        (declare (ignore message))
        (is (eq :greeting phase))))
    (bt:join-thread thread)))

(test socks5-reply-timeout
  "A proxy that goes silent trips the per-step read deadline (Core
g_socks5_recv_timeout, netbase.cpp:40-41)."
  (multiple-value-bind (port thread)
      (%fake-socks5-server `((:read 3) (:sleep 1.5)))
    (with-socks5-client (sock port)
      (signals bl.net:socks5-error
        (bl.net:socks5-connect
         sock "example.com" 18333 :timeout 0.3)))
    (bt:join-thread thread)))

(test socks5-hostname-too-long
  "Destinations over 255 bytes are rejected before any I/O (the DOMAINNAME
length field is one byte, netbase.cpp:396-399)."
  (signals bl.net:socks5-error
    (bl.net:socks5-connect
     nil (make-string 256 :initial-element #\a) 8333)))

;;; --- stream isolation ---------------------------------------------------------

(test socks5-stream-isolation-credentials
  "Successive connections get distinct credentials sharing the per-process
random prefix: \"<16 hex>-<counter>\" (netbase.cpp:748-784)."
  (let ((a (bl.net:next-proxy-credentials))
        (b (bl.net:next-proxy-credentials)))
    (is (not (equal a b)))
    (let ((dash-a (position #\- a))
          (dash-b (position #\- b)))
      (is (eql 16 dash-a))              ; 8 random bytes as hex
      (is (eql 16 dash-b))
      (is (equal (subseq a 0 17) (subseq b 0 17)))   ; same prefix incl. "-"
      (is (every #'digit-char-p (subseq a 17)))      ; counter suffix
      (is (every #'digit-char-p (subseq b 17))))))

;;; --- choke-point integration --------------------------------------------------

(test make-tcp-connection-tunnels-through-proxy
  "With *proxy* configured, make-tcp-connection dials the proxy, runs the
SOCKS5 handshake with fresh isolation credentials, and returns a normal
connection recording the TARGET host/port (Core ConnectThroughProxy,
netbase.cpp:786-810)."
  (multiple-value-bind (port thread captured)
      (%fake-socks5-server
       `((:read 4) (:write #(#x05 #x02))
         (:read-userpass) (:write #(#x01 #x00))
         (:read-connect)
         (:write #(#x05 #x00 #x00 #x01 10 0 0 1 #x20 #x8D))))
    (let ((old-proxy bl.net:*proxy*))
      (unwind-protect
          (progn
            (setf bl.net:*proxy*
                  (bl.net:make-proxy
                   :host "127.0.0.1" :port port :randomize-credentials t))
            (let ((conn (bl.net:make-tcp-connection
                         "seed.example.org" 8333)))
              (is-true conn)
              (when conn
                (is (equal "seed.example.org"
                           (bl.net:connection-host conn)))
                (is-true (bl.net:connection-connected conn))
                (bl.net:close-connection conn))))
        (setf bl.net:*proxy* old-proxy)))
    (bt:join-thread thread)
    ;; The greeting offered USER/PASS (isolation credentials were sent) and
    ;; the CONNECT carried the hostname (never resolved locally).
    (is (equalp #(#x05 #x02 #x00 #x02) (subseq captured 0 4)))
    (let ((hostname (map 'vector #'char-code "seed.example.org")))
      (is-true (search hostname captured :test #'equalp)))))

(test make-tcp-connection-proxy-failure-returns-nil
  "A SOCKS5 failure inside make-tcp-connection preserves its NIL-on-failure
contract (no condition escapes to the dial loop)."
  (multiple-value-bind (port thread)
      (%fake-socks5-server `((:read 4) (:write #(#x05 #xFF))))
    (let ((old-proxy bl.net:*proxy*))
      (unwind-protect
          (progn
            (setf bl.net:*proxy*
                  (bl.net:make-proxy
                   :host "127.0.0.1" :port port :randomize-credentials t))
            (is (null (bl.net:make-tcp-connection
                       "example.com" 8333))))
        (setf bl.net:*proxy* old-proxy)))
    (bt:join-thread thread)))

(defun %closed-loopback-port ()
  "A loopback port with nothing listening on it: bound only to learn the
number, then released. A dial to it is refused immediately and never leaves
this machine."
  (let* ((srv (usocket:socket-listen "127.0.0.1" 0
                                     :element-type '(unsigned-byte 8)
                                     :reuse-address t))
         (port (usocket:get-local-port srv)))
    (usocket:socket-close srv)
    port))

(defun %dial-verdict (host port)
  "(VALUES CONNECTED-P PROXY-FAILED-P) for one MAKE-TCP-CONNECTION dial, with
any socket closed again."
  (multiple-value-bind (conn proxy-failed) (bl.net:make-tcp-connection host port)
    (when conn (bl.net:close-connection conn))
    (values (and conn t) proxy-failed)))

(test make-tcp-connection-flags-only-an-unreachable-proxy
  "MAKE-TCP-CONNECTION's second value is Core's `proxy_connection_failed', and
Core raises it in exactly one place: ConnectThroughProxy sets it when
`proxy.Connect()' returns nothing — the TCP connect to the proxy server — and
leaves it false for every SOCKS5 failure after that, because past that point
the proxy has answered and the verdict is about the TARGET
(netbase.cpp:785-809). ConnectNode reads it to decide whether the address is
charged an addrman attempt at all (net.cpp:494-497).

We returned a bare NIL for all of them, so the dial had no verdict to hand up
and a dead Tor daemon was charged to every onion address the selection tried.

The three cases here are the ones that must not be confused: the proxy is
down, the proxy answers and reports the target unreachable, and there is no
proxy at all."
  (let ((old-proxy bl.net:*proxy*))
    (unwind-protect
         (progn
           ;; 1. The proxy itself is unreachable: T, and the target was never
           ;; dialed.
           (setf bl.net:*proxy*
                 (bl.net:make-proxy :host "127.0.0.1"
                                    :port (%closed-loopback-port)
                                    :randomize-credentials nil))
           (multiple-value-bind (connected proxy-failed)
               (%dial-verdict "example.com" 8333)
             (is-false connected)
             (is-true proxy-failed
                      "an unreachable proxy must not be charged to the target"))
           ;; 2. The proxy answers and refuses the CONNECT with SOCKS5 reply
           ;; 0x05 (\"connection refused\"), which is a verdict about the
           ;; TARGET: Core counts the attempt.
           (multiple-value-bind (port thread)
               (%fake-socks5-server
                `((:read 3) (:write #(#x05 #x00))
                  (:read-connect)
                  (:write #(#x05 #x05 #x00 #x01 0 0 0 0 0 0))))
             (setf bl.net:*proxy*
                   (bl.net:make-proxy :host "127.0.0.1" :port port
                                      :randomize-credentials nil))
             (multiple-value-bind (connected proxy-failed)
                 (%dial-verdict "example.com" 8333)
               (is-false connected)
               (is-false proxy-failed
                         "a proxy that ANSWERED reports on the target, not on itself"))
             (bt:join-thread thread))
           ;; 3. No proxy in the path at all — a loopback target is dialed
           ;; directly whatever -proxy says (Core registers no proxy for
           ;; NET_UNROUTABLE) — so an ordinary refused connect stays NIL.
           (multiple-value-bind (connected proxy-failed)
               (%dial-verdict "127.0.0.1" (%closed-loopback-port))
             (is-false connected)
             (is-false proxy-failed
                       "a direct dial can never be a proxy failure"))
           ;; 4. CONNECT-PEER carries the verdict up unchanged: it is what the
           ;; dial sweeps call, and it is where the addrman recorder reads it.
           (setf bl.net:*proxy*
                 (bl.net:make-proxy :host "127.0.0.1"
                                    :port (%closed-loopback-port)
                                    :randomize-credentials nil))
           (is (equal '(nil t)
                      (multiple-value-list
                       (bl.net:connect-peer "proxy-carveout.invalid" 8333)))
               "connect-peer must pass the proxy verdict through"))
      (setf bl.net:*proxy* old-proxy))))

;;; --- onion dialing (P2) ---------------------------------------------------------

(defparameter +socks5-onion-target+
  "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion"
  "Core's TORv3 test vector address (net_tests.cpp cnetaddr_basic): 56 base32
chars + \".onion\" = 62 bytes on the SOCKS5 wire.")

(test make-tcp-connection-dials-onion-via-onion-proxy
  "A torv3 target dials through *onion-proxy* (-onion, i.e. NOT the general
*proxy*) and the CONNECT carries the exact DOMAINNAME bytes: ATYP 0x03,
length 62, the .onion name, port 8333 hi/lo — Core ConnectNode picks the
NET_ONION proxy and passes ToStringAddr()/GetPort() to ConnectThroughProxy
(net.cpp:449-489)."
  (multiple-value-bind (port thread captured)
      (%fake-socks5-server
       `((:read 3) (:write #(#x05 #x00))          ; NOAUTH
         (:read-connect)
         (:write #(#x05 #x00 #x00 #x01 0 0 0 0 #x00 #x00))))
    (let ((old-proxy bl.net:*proxy*)
          (old-onion bl.net:*onion-proxy*))
      (unwind-protect
          (progn
            ;; General proxy points NOWHERE dialable: proves the onion dial
            ;; uses the -onion proxy, not -proxy.
            (setf bl.net:*proxy*
                  (bl.net:make-proxy
                   :host "192.0.2.1" :port 1 :randomize-credentials nil))
            (setf bl.net:*onion-proxy*
                  (bl.net:make-proxy
                   :host "127.0.0.1" :port port :randomize-credentials nil))
            (let ((conn (bl.net:make-tcp-connection
                         +socks5-onion-target+ 8333)))
              (is-true conn)
              (when conn
                (is (equal +socks5-onion-target+
                           (bl.net:connection-host conn)))
                (is (= 8333 (bl.net:connection-port conn)))
                (bl.net:close-connection conn))))
        (setf bl.net:*proxy* old-proxy
              bl.net:*onion-proxy* old-onion)))
    (bt:join-thread thread)
    ;; Exact wire bytes: greeting 05 01 00, CONNECT 05 01 00 03 3E <name> 20 8D.
    (is (= (+ 3 4 1 62 2) (length captured)))
    (is (equalp #(#x05 #x01 #x00) (subseq captured 0 3)))
    (is (equalp #(#x05 #x01 #x00 #x03 62) (subseq captured 3 8)))
    (is (equalp (map 'vector #'char-code +socks5-onion-target+)
                (subseq captured 8 70)))
    (is (= #x20 (aref captured 70)))    ; 8333 = 0x208D
    (is (= #x8D (aref captured 71)))))

(test make-tcp-connection-refuses-onion-without-proxy
  "With no Tor proxy configured, an onion dial is refused up front — NIL, no
socket, no DNS lookup of the onion name. The no-proxy node is provably
unchanged: onion addresses can be stored but never dialed."
  (let ((old-proxy bl.net:*proxy*)
        (old-onion bl.net:*onion-proxy*))
    (unwind-protect
        (progn
          (setf bl.net:*proxy* nil
                bl.net:*onion-proxy* nil)
          (is (null (bl.net:make-tcp-connection
                     +socks5-onion-target+ 8333)))
          ;; I2P targets are refused too (SAM is P4).
          (is (null (bl.net:make-tcp-connection
                     "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p"
                     0))))
      (setf bl.net:*proxy* old-proxy
            bl.net:*onion-proxy* old-onion))))

;;; --- DNS discipline -------------------------------------------------------------

(test discover-peers-skips-local-dns-when-proxied
  "With a proxy set, DNS seeds are returned as hostname dial targets instead
of being resolved locally (Core net.cpp:2353-2358 AddAddrFetch)."
  (let ((bl.net:*proxy*
          (bl.net:make-proxy :host "127.0.0.1" :port 9050)))
    (is (equal '("seed.example.org" "dnsseed.example.net")
               (bl.net:discover-peers
                '("seed.example.org" "dnsseed.example.net"))))))

;;; --- config wiring ----------------------------------------------------------------

(test conf-parse-proxy-forms
  "-proxy value parsing: default port 9050, explicit port, \"0\" clears,
bracketed IPv6."
  (multiple-value-bind (host port) (bl.cfg:conf-parse-proxy "127.0.0.1")
    (is (equal "127.0.0.1" host))
    (is (= 9050 port)))
  (multiple-value-bind (host port)
      (bl.cfg:conf-parse-proxy "127.0.0.1:9150")
    (is (equal "127.0.0.1" host))
    (is (= 9150 port)))
  (is (null (bl.cfg:conf-parse-proxy "0")))
  (is (null (bl.cfg:conf-parse-proxy "")))
  (multiple-value-bind (host port) (bl.cfg:conf-parse-proxy "[::1]:9150")
    (is (equal "::1" host))
    (is (= 9150 port)))
  (multiple-value-bind (host port) (bl.cfg:conf-parse-proxy "[::1]")
    (is (equal "::1" host))
    (is (= 9050 port))))

(test apply-config-globals-proxy
  "-proxy sets networking's *proxy* (randomize default on), -proxyrandomize=0
disables isolation, -noproxy/-proxy=0 clears, -onion overrides and defaults
to -proxy."
  (let ((old-proxy bl.net:*proxy*)
        (old-onion bl.net:*onion-proxy*)
        ;; apply-config-globals also recomputes the reachable-network set
        ;; (onion follows the proxy) — keep that from leaking out of the test.
        (bl.net:*reachable-networks*
          bl.net:*reachable-networks*)
        (bl.net:*cjdns-reachable*
          bl.net:*cjdns-reachable*))
    (unwind-protect
        (progn
          ;; -proxy with default randomize; onion follows proxy.
          (apply-config-globals '(("proxy" . "127.0.0.1:9150")))
          (let ((p bl.net:*proxy*))
            (is-true p)
            (is (equal "127.0.0.1" (bl.net:proxy-host p)))
            (is (= 9150 (bl.net:proxy-port p)))
            (is-true (bl.net:proxy-randomize-credentials p))
            (is (eq p bl.net:*onion-proxy*)))
          ;; -proxyrandomize=0 disables stream isolation.
          (apply-config-globals
           '(("proxy" . "10.0.0.1") ("proxyrandomize" . "0")))
          (let ((p bl.net:*proxy*))
            (is (= 9050 (bl.net:proxy-port p)))
            (is-false (bl.net:proxy-randomize-credentials p)))
          ;; -onion overrides the onion proxy only.
          (apply-config-globals
           '(("proxy" . "10.0.0.1") ("onion" . "10.0.0.2:9051")))
          (is (equal "10.0.0.1" (bl.net:proxy-host
                                 bl.net:*proxy*)))
          (is (equal "10.0.0.2" (bl.net:proxy-host
                                 bl.net:*onion-proxy*)))
          (is (= 9051 (bl.net:proxy-port
                       bl.net:*onion-proxy*)))
          ;; -noproxy parses as proxy=0 and clears the proxy.
          (apply-config-globals
           (bl.cfg:parse-cli-args '("-noproxy")))
          (is (null bl.net:*proxy*)))
      (setf bl.net:*proxy* old-proxy
            bl.net:*onion-proxy* old-onion))))

(test onion-zero-disables-tor-dialing
  "-onion=0 (or -noonion) disables onion dialing even with -proxy set (Core
init.cpp:1766-1780: onion_proxy cleared, NET_ONION removed from the reachable
set): *onion-proxy* NIL, torv3 neither reachable nor dialable, and an onion
dial is refused."
  (let ((old-proxy bl.net:*proxy*)
        (old-onion bl.net:*onion-proxy*)
        (bl.net:*reachable-networks*
          bl.net:*reachable-networks*)
        (bl.net:*cjdns-reachable*
          bl.net:*cjdns-reachable*))
    (unwind-protect
        (progn
          (apply-config-globals
           '(("proxy" . "127.0.0.1:9150") ("onion" . "0")))
          (is-true bl.net:*proxy*)
          (is (null bl.net:*onion-proxy*))
          (is-false (bl.net:reachable-network-p :torv3))
          (is-false (bl.net:dialable-network-p :torv3))
          (multiple-value-bind (proxy refusal)
              (bl.net:proxy-for-target +socks5-onion-target+)
            (is (null proxy))
            (is (stringp refusal)))
          ;; -noonion parses to onion=0 and behaves identically.
          (apply-config-globals
           (append (bl.cfg:parse-cli-args '("-noonion"))
                   '(("proxy" . "127.0.0.1:9150"))))
          (is (null bl.net:*onion-proxy*))
          ;; And plain -proxy (no -onion) re-enables: torv3 dialable again.
          (apply-config-globals '(("proxy" . "127.0.0.1:9150")))
          (is-true (bl.net:dialable-network-p :torv3))
          (is-true (bl.net:reachable-network-p :torv3)))
      (setf bl.net:*proxy* old-proxy
            bl.net:*onion-proxy* old-onion))))

(test proxy-is-not-used-for-unroutable-targets
  "Core never proxies an unroutable target, and reaches that structurally:
GetNetwork() answers NET_UNROUTABLE for anything IsRoutable() rejects
(netaddress.cpp:496-505), and no proxy is ever registered for that
pseudo-network, so GetProxy fails and ConnectNode dials directly
(net.cpp:486-491).

Ours sent EVERY dial through -proxy. That is not a corner case: Core's
rpc_net.py gives every node -proxy=127.0.0.1:1, a deliberately dead proxy
\"to make sure no actual connections to public IPs are attempted\", and then
expects those nodes to connect to each other over loopback. A node that
proxies loopback cannot be tested that way and cannot reach its own peers on
any private network.

Hostnames keep the proxy on purpose — Core routes name lookups through it
precisely so the name does not leak to local DNS."
  (let ((bl.net:*proxy*
          (bl.net:make-proxy :host "127.0.0.1" :port 1)))
    (dolist (direct '("127.0.0.1" "127.5.5.5" "10.0.0.1" "172.16.0.1"
                      "192.168.1.5" "169.254.1.1" "100.64.0.1" "::1"
                      "fe80::1"))
      (is (null (bl.net:proxy-for-target direct))
          "~A was dialed through the proxy" direct))
    ;; Documentation space (203.0.113/24) stays PROXIED here, unlike in Core:
    ;; this tree treats it as routable on purpose so fixtures can use it as a
    ;; public stand-in. See %TARGET-UNROUTABLE-P.
    ;; fc00::/7 stays proxied: Core's IsRFC4193() is guarded by IsIPv6(), a
    ;; NETWORK-TAG check, so a CJDNS address on the same prefix is routable and
    ;; an unsuffixed -proxy covers it. A bare host string carries no tag.
    (dolist (proxied '("8.8.8.8" "1.1.1.1" "2001:db8::1" "example.com"
                       "203.0.113.7" "fc00:1:2:3:4:5:6:7"))
      (is (not (null (bl.net:proxy-for-target proxied)))
          "~A skipped the proxy" proxied))
    ;; The positive control: with no proxy configured, everything is direct,
    ;; so a test that only asserted NIL above would pass against a broken
    ;; classifier.
    (let ((bl.net:*proxy* nil))
      (is (null (bl.net:proxy-for-target "8.8.8.8"))))))

(test proxy-soft-defaults-listen-off
  "-proxy soft-sets listen off (Core init.cpp:786-790), but an explicit
-listen wins, and -proxy=0 leaves listening alone.

Asserted as a VALUE rather than as key presence. The soft-set chain now
computes one definite effective -listen, the way Core's
InitParameterInteraction does, so the plist always carries it; \"absent\"
stopped being how the default is expressed. START-NODE's own default is T, so
an explicit T and an absent key mean the same thing to the caller — the
distinction the old assertion rested on was in the plist, not in behaviour."
  (let ((plist (bl::config-alist->start-node-plist
                '(("proxy" . "127.0.0.1")) :testnet4)))
    (is (null (getf plist :listen 'missing))))
  (let ((plist (bl::config-alist->start-node-plist
                '(("proxy" . "127.0.0.1") ("listen" . "1")) :testnet4)))
    (is (eq t (getf plist :listen))))
  (let ((plist (bl::config-alist->start-node-plist
                '(("proxy" . "0")) :testnet4)))
    (is (eq t (getf plist :listen 'missing))))
  ;; -bind wins over -proxy, for the same reason it wins over -connect: Core
  ;; applies it FIRST (init.cpp:766-771) and says "you want to listen on it
  ;; even when -connect or -proxy is specified".
  (let ((plist (bl::config-alist->start-node-plist
                '(("proxy" . "127.0.0.1") ("bind" . "127.0.0.1")) :testnet4)))
    (is (eq t (getf plist :listen)))))
