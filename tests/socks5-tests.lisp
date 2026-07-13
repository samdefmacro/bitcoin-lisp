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
    (bitcoin-lisp.networking:socks5-error (e)
      (values (bitcoin-lisp.networking::socks5-error-message e)
              (bitcoin-lisp.networking:socks5-error-phase e)))))

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
      (is-true (bitcoin-lisp.networking:socks5-connect
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
      (is-true (bitcoin-lisp.networking:socks5-connect
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
      (is-true (bitcoin-lisp.networking:socks5-connect
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
           (lambda () (bitcoin-lisp.networking:socks5-connect
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
                  (lambda () (bitcoin-lisp.networking:socks5-connect
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
           (lambda () (bitcoin-lisp.networking:socks5-connect
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
      (signals bitcoin-lisp.networking:socks5-error
        (bitcoin-lisp.networking:socks5-connect
         sock "example.com" 18333 :timeout 0.3)))
    (bt:join-thread thread)))

(test socks5-hostname-too-long
  "Destinations over 255 bytes are rejected before any I/O (the DOMAINNAME
length field is one byte, netbase.cpp:396-399)."
  (signals bitcoin-lisp.networking:socks5-error
    (bitcoin-lisp.networking:socks5-connect
     nil (make-string 256 :initial-element #\a) 8333)))

;;; --- stream isolation ---------------------------------------------------------

(test socks5-stream-isolation-credentials
  "Successive connections get distinct credentials sharing the per-process
random prefix: \"<16 hex>-<counter>\" (netbase.cpp:748-784)."
  (let ((a (bitcoin-lisp.networking:next-proxy-credentials))
        (b (bitcoin-lisp.networking:next-proxy-credentials)))
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
    (let ((old-proxy bitcoin-lisp.networking:*proxy*))
      (unwind-protect
          (progn
            (setf bitcoin-lisp.networking:*proxy*
                  (bitcoin-lisp.networking:make-proxy
                   :host "127.0.0.1" :port port :randomize-credentials t))
            (let ((conn (bitcoin-lisp.networking:make-tcp-connection
                         "seed.example.org" 8333)))
              (is-true conn)
              (when conn
                (is (equal "seed.example.org"
                           (bitcoin-lisp.networking:connection-host conn)))
                (is-true (bitcoin-lisp.networking:connection-connected conn))
                (bitcoin-lisp.networking:close-connection conn))))
        (setf bitcoin-lisp.networking:*proxy* old-proxy)))
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
    (let ((old-proxy bitcoin-lisp.networking:*proxy*))
      (unwind-protect
          (progn
            (setf bitcoin-lisp.networking:*proxy*
                  (bitcoin-lisp.networking:make-proxy
                   :host "127.0.0.1" :port port :randomize-credentials t))
            (is (null (bitcoin-lisp.networking:make-tcp-connection
                       "example.com" 8333))))
        (setf bitcoin-lisp.networking:*proxy* old-proxy)))
    (bt:join-thread thread)))

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
    (let ((old-proxy bitcoin-lisp.networking:*proxy*)
          (old-onion bitcoin-lisp.networking:*onion-proxy*))
      (unwind-protect
          (progn
            ;; General proxy points NOWHERE dialable: proves the onion dial
            ;; uses the -onion proxy, not -proxy.
            (setf bitcoin-lisp.networking:*proxy*
                  (bitcoin-lisp.networking:make-proxy
                   :host "192.0.2.1" :port 1 :randomize-credentials nil))
            (setf bitcoin-lisp.networking:*onion-proxy*
                  (bitcoin-lisp.networking:make-proxy
                   :host "127.0.0.1" :port port :randomize-credentials nil))
            (let ((conn (bitcoin-lisp.networking:make-tcp-connection
                         +socks5-onion-target+ 8333)))
              (is-true conn)
              (when conn
                (is (equal +socks5-onion-target+
                           (bitcoin-lisp.networking:connection-host conn)))
                (is (= 8333 (bitcoin-lisp.networking::connection-port conn)))
                (bitcoin-lisp.networking:close-connection conn))))
        (setf bitcoin-lisp.networking:*proxy* old-proxy
              bitcoin-lisp.networking:*onion-proxy* old-onion)))
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
  (let ((old-proxy bitcoin-lisp.networking:*proxy*)
        (old-onion bitcoin-lisp.networking:*onion-proxy*))
    (unwind-protect
        (progn
          (setf bitcoin-lisp.networking:*proxy* nil
                bitcoin-lisp.networking:*onion-proxy* nil)
          (is (null (bitcoin-lisp.networking:make-tcp-connection
                     +socks5-onion-target+ 8333)))
          ;; I2P targets are refused too (SAM is P4).
          (is (null (bitcoin-lisp.networking:make-tcp-connection
                     "ukeu3k5oycgaauneqgtnvselmt4yemvoilkln7jpvamvfx7dnkdq.b32.i2p"
                     0))))
      (setf bitcoin-lisp.networking:*proxy* old-proxy
            bitcoin-lisp.networking:*onion-proxy* old-onion))))

;;; --- DNS discipline -------------------------------------------------------------

(test discover-peers-skips-local-dns-when-proxied
  "With a proxy set, DNS seeds are returned as hostname dial targets instead
of being resolved locally (Core net.cpp:2353-2358 AddAddrFetch)."
  (let ((bitcoin-lisp.networking:*proxy*
          (bitcoin-lisp.networking:make-proxy :host "127.0.0.1" :port 9050)))
    (is (equal '("seed.example.org" "dnsseed.example.net")
               (bitcoin-lisp.networking:discover-peers
                '("seed.example.org" "dnsseed.example.net"))))))

;;; --- config wiring ----------------------------------------------------------------

(test conf-parse-proxy-forms
  "-proxy value parsing: default port 9050, explicit port, \"0\" clears,
bracketed IPv6."
  (multiple-value-bind (host port) (bitcoin-lisp::conf-parse-proxy "127.0.0.1")
    (is (equal "127.0.0.1" host))
    (is (= 9050 port)))
  (multiple-value-bind (host port)
      (bitcoin-lisp::conf-parse-proxy "127.0.0.1:9150")
    (is (equal "127.0.0.1" host))
    (is (= 9150 port)))
  (is (null (bitcoin-lisp::conf-parse-proxy "0")))
  (is (null (bitcoin-lisp::conf-parse-proxy "")))
  (multiple-value-bind (host port) (bitcoin-lisp::conf-parse-proxy "[::1]:9150")
    (is (equal "::1" host))
    (is (= 9150 port)))
  (multiple-value-bind (host port) (bitcoin-lisp::conf-parse-proxy "[::1]")
    (is (equal "::1" host))
    (is (= 9050 port))))

(test apply-config-globals-proxy
  "-proxy sets networking's *proxy* (randomize default on), -proxyrandomize=0
disables isolation, -noproxy/-proxy=0 clears, -onion overrides and defaults
to -proxy."
  (let ((old-proxy bitcoin-lisp.networking:*proxy*)
        (old-onion bitcoin-lisp.networking:*onion-proxy*)
        ;; apply-config-globals also recomputes the reachable-network set
        ;; (onion follows the proxy) — keep that from leaking out of the test.
        (bitcoin-lisp.networking:*reachable-networks*
          bitcoin-lisp.networking:*reachable-networks*)
        (bitcoin-lisp.networking:*cjdns-reachable*
          bitcoin-lisp.networking:*cjdns-reachable*))
    (unwind-protect
        (progn
          ;; -proxy with default randomize; onion follows proxy.
          (bitcoin-lisp::apply-config-globals '(("proxy" . "127.0.0.1:9150")))
          (let ((p bitcoin-lisp.networking:*proxy*))
            (is-true p)
            (is (equal "127.0.0.1" (bitcoin-lisp.networking:proxy-host p)))
            (is (= 9150 (bitcoin-lisp.networking:proxy-port p)))
            (is-true (bitcoin-lisp.networking:proxy-randomize-credentials p))
            (is (eq p bitcoin-lisp.networking:*onion-proxy*)))
          ;; -proxyrandomize=0 disables stream isolation.
          (bitcoin-lisp::apply-config-globals
           '(("proxy" . "10.0.0.1") ("proxyrandomize" . "0")))
          (let ((p bitcoin-lisp.networking:*proxy*))
            (is (= 9050 (bitcoin-lisp.networking:proxy-port p)))
            (is-false (bitcoin-lisp.networking:proxy-randomize-credentials p)))
          ;; -onion overrides the onion proxy only.
          (bitcoin-lisp::apply-config-globals
           '(("proxy" . "10.0.0.1") ("onion" . "10.0.0.2:9051")))
          (is (equal "10.0.0.1" (bitcoin-lisp.networking:proxy-host
                                 bitcoin-lisp.networking:*proxy*)))
          (is (equal "10.0.0.2" (bitcoin-lisp.networking:proxy-host
                                 bitcoin-lisp.networking:*onion-proxy*)))
          (is (= 9051 (bitcoin-lisp.networking:proxy-port
                       bitcoin-lisp.networking:*onion-proxy*)))
          ;; -noproxy parses as proxy=0 and clears the proxy.
          (bitcoin-lisp::apply-config-globals
           (bitcoin-lisp::parse-cli-args '("-noproxy")))
          (is (null bitcoin-lisp.networking:*proxy*)))
      (setf bitcoin-lisp.networking:*proxy* old-proxy
            bitcoin-lisp.networking:*onion-proxy* old-onion))))

(test onion-zero-disables-tor-dialing
  "-onion=0 (or -noonion) disables onion dialing even with -proxy set (Core
init.cpp:1766-1780: onion_proxy cleared, NET_ONION removed from the reachable
set): *onion-proxy* NIL, torv3 neither reachable nor dialable, and an onion
dial is refused."
  (let ((old-proxy bitcoin-lisp.networking:*proxy*)
        (old-onion bitcoin-lisp.networking:*onion-proxy*)
        (bitcoin-lisp.networking:*reachable-networks*
          bitcoin-lisp.networking:*reachable-networks*)
        (bitcoin-lisp.networking:*cjdns-reachable*
          bitcoin-lisp.networking:*cjdns-reachable*))
    (unwind-protect
        (progn
          (bitcoin-lisp::apply-config-globals
           '(("proxy" . "127.0.0.1:9150") ("onion" . "0")))
          (is-true bitcoin-lisp.networking:*proxy*)
          (is (null bitcoin-lisp.networking:*onion-proxy*))
          (is-false (bitcoin-lisp.networking:reachable-network-p :torv3))
          (is-false (bitcoin-lisp.networking:dialable-network-p :torv3))
          (multiple-value-bind (proxy refusal)
              (bitcoin-lisp.networking:proxy-for-target +socks5-onion-target+)
            (is (null proxy))
            (is (stringp refusal)))
          ;; -noonion parses to onion=0 and behaves identically.
          (bitcoin-lisp::apply-config-globals
           (append (bitcoin-lisp::parse-cli-args '("-noonion"))
                   '(("proxy" . "127.0.0.1:9150"))))
          (is (null bitcoin-lisp.networking:*onion-proxy*))
          ;; And plain -proxy (no -onion) re-enables: torv3 dialable again.
          (bitcoin-lisp::apply-config-globals '(("proxy" . "127.0.0.1:9150")))
          (is-true (bitcoin-lisp.networking:dialable-network-p :torv3))
          (is-true (bitcoin-lisp.networking:reachable-network-p :torv3)))
      (setf bitcoin-lisp.networking:*proxy* old-proxy
            bitcoin-lisp.networking:*onion-proxy* old-onion))))

(test proxy-soft-defaults-listen-off
  "-proxy soft-sets listen off (Core init.cpp:786-790), but an explicit
-listen wins, and -proxy=0 leaves listening alone."
  (let ((plist (bitcoin-lisp::config-alist->start-node-plist
                '(("proxy" . "127.0.0.1")) :testnet4)))
    (is (null (getf plist :listen 'missing))))
  (let ((plist (bitcoin-lisp::config-alist->start-node-plist
                '(("proxy" . "127.0.0.1") ("listen" . "1")) :testnet4)))
    (is (eq t (getf plist :listen))))
  (let ((plist (bitcoin-lisp::config-alist->start-node-plist
                '(("proxy" . "0")) :testnet4)))
    (is (eq 'missing (getf plist :listen 'missing)))))
