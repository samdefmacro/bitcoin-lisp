(in-package #:bitcoin-lisp.tests)

;;; Tor control client tests (Core torcontrol.cpp).
;;;
;;; Pure-parser tests port Core's own torcontrol_tests.cpp vectors verbatim
;;; (SplitTorReplyLine / ParseTorReplyMapping). SAFECOOKIE HMAC vectors were
;;; computed independently with python3 hmac/hashlib (never hand-transcribed).
;;; The end-to-end tests drive the real torcontrol thread against a fake
;;; in-process control server on loopback: line protocol, NULL and SAFECOOKIE
;;; auth, ADD_ONION (fresh + restored key), key persistence + permissions,
;;; error replies, and the resulting local-address registration.

(def-suite :torcontrol-tests
  :description "Tor control client, onion service, local-address self-advertisement"
  :in :bitcoin-lisp-tests)

(in-suite :torcontrol-tests)

;;; --- helpers -----------------------------------------------------------------

(defun %wait-until (predicate &optional (timeout 10))
  "Poll PREDICATE until it returns non-NIL or TIMEOUT seconds pass."
  (let ((deadline (+ (get-internal-real-time)
                     (round (* timeout internal-time-units-per-second)))))
    (loop (let ((v (funcall predicate)))
            (when v (return v))
            (when (> (get-internal-real-time) deadline) (return nil))
            (sleep 0.05)))))

(defun %torcontrol-temp-dir ()
  (let ((dir (merge-pathnames (format nil "bitcoin-lisp-torcontrol-~D/"
                                      (random 100000000))
                              (uiop:temporary-directory))))
    (ensure-directories-exist dir)
    dir))

(defmacro with-tor-globals (&body body)
  "Save/restore the networking globals the torcontrol client mutates, and
start each test from a clean slate (no proxies, no local addresses,
default reachability)."
  `(let ((old-proxy bl.net:*proxy*)
         (old-onion bl.net:*onion-proxy*)
         (old-explicit bl.net:*onion-proxy-explicit*)
         (old-reach bl.net:*reachable-networks*)
         (old-onlynet bl.net:*onlynet-networks*)
         (old-locals (bl.net:local-addresses)))
     (unwind-protect
          (progn
            (setf bl.net:*proxy* nil
                  bl.net:*onion-proxy* nil
                  bl.net:*onion-proxy-explicit* nil
                  bl.net:*reachable-networks* '(:ipv4 :ipv6)
                  bl.net:*onlynet-networks* nil)
            (bl.net:clear-local-addresses)
            ,@body)
       (setf bl.net:*proxy* old-proxy
             bl.net:*onion-proxy* old-onion
             bl.net:*onion-proxy-explicit* old-explicit
             bl.net:*reachable-networks* old-reach
             bl.net:*onlynet-networks* old-onlynet)
       ;; old-locals is already a private snapshot (local-addresses copies).
       (bt:with-lock-held (bl.net::*local-addresses-lock*)
         (setf bl.net::*local-addresses* old-locals)))))

(defun %fake-tor-server (handler)
  "One-shot fake Tor control server on 127.0.0.1: accept a single client,
then per received CRLF line push it onto the returned RECEIVED list and send
each string (funcall HANDLER line) back CRLF-terminated; HANDLER returning
NIL (or EOF) ends the session. Returns (values PORT THREAD RECEIVED-FN) where
RECEIVED-FN returns the command lines received so far, newest last."
  (let* ((srv (usocket:socket-listen "127.0.0.1" 0
                                     :element-type '(unsigned-byte 8)
                                     :reuse-address t))
         (port (usocket:get-local-port srv))
         (received '())
         (lock (bt:make-lock "fake-tor-received"))
         (thread
           (bt:make-thread
            (lambda ()
              (unwind-protect
                   (ignore-errors
                     (let* ((client (usocket:socket-accept
                                     srv :element-type '(unsigned-byte 8)))
                            (stream (usocket:socket-stream client)))
                       (unwind-protect
                            (flet ((read-line* ()
                                     (let ((out (make-array 64 :element-type 'character
                                                               :adjustable t :fill-pointer 0)))
                                       (loop for byte = (read-byte stream nil nil)
                                             do (cond
                                                  ((null byte)
                                                   (return-from read-line* nil))
                                                  ((= byte 10)
                                                   (let ((n (fill-pointer out)))
                                                     (when (and (plusp n)
                                                                (char= (aref out (1- n)) #\Return))
                                                       (decf (fill-pointer out))))
                                                   (return-from read-line*
                                                     (coerce out 'string)))
                                                  (t (vector-push-extend
                                                      (code-char byte) out)))))))
                              (loop for line = (read-line*)
                                    while line
                                    do (bt:with-lock-held (lock)
                                         (push line received))
                                       (let ((replies (funcall handler line)))
                                         (unless replies (return))
                                         (dolist (r replies)
                                           (write-sequence
                                            (map '(vector (unsigned-byte 8)) #'char-code r)
                                            stream)
                                           (write-sequence #(13 10) stream))
                                         (force-output stream))))
                         (ignore-errors (usocket:socket-close client)))))
                (ignore-errors (usocket:socket-close srv))))
            :name "fake-tor-server")))
    (values port thread (lambda () (bt:with-lock-held (lock) (reverse received))))))

(defun %hx (hex) (bl.crypto:hex-to-bytes hex))

;;; --- reply line framing ------------------------------------------------------

(test tor-parse-reply-line
  "Reply lines are '<3-digit status><sep><data>'; short lines (<4 chars) are
skipped; a non-numeric status parses as 0 (Core readcb + ToIntegral
.value_or(0), torcontrol.cpp:96-105)."
  (multiple-value-bind (code sep data)
      (bl.net::parse-tor-reply-line "250 OK")
    (is (= 250 code))
    (is (char= #\Space sep))
    (is (string= "OK" data)))
  (multiple-value-bind (code sep data)
      (bl.net::parse-tor-reply-line "250-AUTH METHODS=NULL")
    (is (= 250 code))
    (is (char= #\- sep))
    (is (string= "AUTH METHODS=NULL" data)))
  (multiple-value-bind (code sep data)
      (bl.net::parse-tor-reply-line "250+onions/current=")
    (is (= 250 code))
    (is (char= #\+ sep))
    (is (string= "onions/current=" data)))
  (multiple-value-bind (code sep data)
      (bl.net::parse-tor-reply-line "650 CIRC 1000 EXTENDED")
    (is (= 650 code))
    (is (char= #\Space sep))
    (is (string= "CIRC 1000 EXTENDED" data)))
  ;; Short lines are skipped by the reader.
  (is-false (bl.net::parse-tor-reply-line ""))
  (is-false (bl.net::parse-tor-reply-line "250"))
  (is-false (bl.net::parse-tor-reply-line "OK"))
  ;; Garbage status -> code 0.
  (is (= 0 (bl.net::parse-tor-reply-line "abc def"))))

;;; --- SplitTorReplyLine (Core torcontrol_tests.cpp vectors) -------------------

(defun %check-split (input command args)
  (multiple-value-bind (c a)
      (bl.net::split-tor-reply-line input)
    (is (string= command c) "command of ~S" input)
    (is (string= args a) "args of ~S" input)))

(test tor-split-reply-line
  "SplitTorReplyLine vectors from Core torcontrol_tests.cpp."
  (%check-split "PROTOCOLINFO PIVERSION" "PROTOCOLINFO" "PIVERSION")
  (%check-split "AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"/home/x/.tor/control_auth_cookie\""
                "AUTH" "METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"/home/x/.tor/control_auth_cookie\"")
  (%check-split "AUTH METHODS=NULL" "AUTH" "METHODS=NULL")
  (%check-split "AUTH METHODS=HASHEDPASSWORD" "AUTH" "METHODS=HASHEDPASSWORD")
  (%check-split "VERSION Tor=\"0.2.9.8 (git-a0df013ea241b026)\""
                "VERSION" "Tor=\"0.2.9.8 (git-a0df013ea241b026)\"")
  (%check-split "AUTHCHALLENGE SERVERHASH=aaaa SERVERNONCE=bbbb"
                "AUTHCHALLENGE" "SERVERHASH=aaaa SERVERNONCE=bbbb")
  (%check-split "COMMAND" "COMMAND" "")
  (%check-split "COMMAND SOME  ARGS" "COMMAND" "SOME  ARGS")
  (%check-split "COMMAND  ARGS" "COMMAND" " ARGS")
  (%check-split "COMMAND   EVEN+more  ARGS" "COMMAND" "  EVEN+more  ARGS"))

;;; --- ParseTorReplyMapping (Core torcontrol_tests.cpp vectors) ----------------

(defun %check-mapping (input expected)
  "EXPECTED is an alist; order matters (Core compares std::map iteration, but
every vector's keys arrive pre-sorted or singleton, and we additionally pin
arrival order)."
  (let ((ret (bl.net::parse-tor-reply-mapping input)))
    (is (= (length expected) (length ret)) "size for ~S: got ~S" input ret)
    (loop for (ek . ev) in expected
          for (rk . rv) in ret
          do (is (string= ek rk) "key for ~S" input)
             (is (string= ev rv) "value of ~A for ~S" ek input))))

(test tor-parse-reply-mapping-normal
  "ParseTorReplyMapping vectors from Core torcontrol_tests.cpp: normal data."
  (%check-mapping "METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"/home/x/.tor/control_auth_cookie\""
                  '(("METHODS" . "COOKIE,SAFECOOKIE")
                    ("COOKIEFILE" . "/home/x/.tor/control_auth_cookie")))
  (%check-mapping "METHODS=NULL" '(("METHODS" . "NULL")))
  (%check-mapping "METHODS=HASHEDPASSWORD" '(("METHODS" . "HASHEDPASSWORD")))
  (%check-mapping "Tor=\"0.2.9.8 (git-a0df013ea241b026)\""
                  '(("Tor" . "0.2.9.8 (git-a0df013ea241b026)")))
  (%check-mapping "SERVERHASH=aaaa SERVERNONCE=bbbb"
                  '(("SERVERHASH" . "aaaa") ("SERVERNONCE" . "bbbb")))
  (%check-mapping "ServiceID=exampleonion1234"
                  '(("ServiceID" . "exampleonion1234")))
  (%check-mapping "PrivateKey=RSA1024:BLOB" '(("PrivateKey" . "RSA1024:BLOB")))
  (%check-mapping "ClientAuth=bob:BLOB" '(("ClientAuth" . "bob:BLOB")))
  (%check-mapping "Foo=Bar=Baz Spam=Eggs"
                  '(("Foo" . "Bar=Baz") ("Spam" . "Eggs")))
  (%check-mapping "Foo=\"Bar=Baz\"" '(("Foo" . "Bar=Baz")))
  (%check-mapping "Foo=\"Bar Baz\"" '(("Foo" . "Bar Baz"))))

(test tor-parse-reply-mapping-escapes
  "ParseTorReplyMapping vectors from Core torcontrol_tests.cpp: escapes,
octals, error and OptArguments cases."
  (%check-mapping "Foo=\"Bar\\ Baz\"" '(("Foo" . "Bar Baz")))
  (%check-mapping "Foo=\"Bar\\Baz\"" '(("Foo" . "BarBaz")))
  (%check-mapping "Foo=\"Bar\\@Baz\"" '(("Foo" . "Bar@Baz")))
  (%check-mapping "Foo=\"Bar\\\"Baz\" Spam=\"\\\"Eggs\\\"\""
                  '(("Foo" . "Bar\"Baz") ("Spam" . "\"Eggs\"")))
  (%check-mapping "Foo=\"Bar\\\\Baz\"" '(("Foo" . "Bar\\Baz")))
  ;; C escapes + octals (the torture vector).
  (let ((ret (bl.net::parse-tor-reply-mapping
              "Foo=\"Bar\\nBaz\\t\" Spam=\"\\rEggs\" Octals=\"\\1a\\11\\17\\18\\81\\377\\378\\400\\2222\" Final=Check")))
    (is (= 4 (length ret)))
    (is (string= (format nil "Bar~ABaz~A" #\Newline #\Tab)
                 (cdr (assoc "Foo" ret :test #'string=))))
    (is (string= (format nil "~AEggs" #\Return)
                 (cdr (assoc "Spam" ret :test #'string=))))
    (is (equalp (map 'list #'char-code (cdr (assoc "Octals" ret :test #'string=)))
                ;; \1 a \11 \17 \1 8 8 1 \377 \37 8 \40 0 \222 2
                (list 1 (char-code #\a) 9 15 1 (char-code #\8) (char-code #\8)
                      (char-code #\1) 255 31 (char-code #\8) 32 (char-code #\0)
                      146 (char-code #\2))))
    (is (string= "Check" (cdr (assoc "Final" ret :test #'string=)))))
  (%check-mapping "Valid=Mapping Escaped=\"Escape\\\\\""
                  '(("Valid" . "Mapping") ("Escaped" . "Escape\\")))
  ;; Unterminated quote (trailing escaped quote) -> error -> empty.
  (%check-mapping "Valid=Mapping Bare=\"Escape\\\"" '())
  (%check-mapping "OneOctal=\"OneEnd\\1\" TwoOctal=\"TwoEnd\\11\""
                  `(("OneOctal" . ,(format nil "OneEnd~A" (code-char 1)))
                    ("TwoOctal" . ,(format nil "TwoEnd~A" (code-char 9)))))
  ;; Null escape.
  (let ((ret (bl.net::parse-tor-reply-mapping "Null=\"\\0\"")))
    (is (= 1 (length ret)))
    (is (string= "Null" (car (first ret))))
    (is (= 1 (length (cdr (first ret)))))
    (is (= 0 (char-code (char (cdr (first ret)) 0)))))
  ;; OptArguments terminates parsing.
  (%check-mapping "SOME=args,here MORE optional=arguments  here"
                  '(("SOME" . "args,here")))
  ;; Effectively-invalid inputs -> empty.
  (%check-mapping "ARGS" '())
  (%check-mapping "MORE ARGS" '())
  (%check-mapping "MORE  ARGS" '())
  (%check-mapping "EVEN more=ARGS" '())
  (%check-mapping "EVEN+more ARGS" '()))

;;; --- SAFECOOKIE HMAC (python3-derived vectors) -------------------------------

(test tor-safecookie-hmac-vectors
  "ComputeResponse (torcontrol.cpp:504-513): HMAC-SHA256 with the exact Tor
key strings over cookie||clientNonce||serverNonce. Vectors computed with
python3 hmac/hashlib (scratchpad safecookie_vectors.py), not hand-derived."
  (flet ((server (cookie cn sn)
           (bl.net::compute-safecookie-response
            bl.net::+tor-safe-serverkey+ cookie cn sn))
         (client (cookie cn sn)
           (bl.net::compute-safecookie-response
            bl.net::+tor-safe-clientkey+ cookie cn sn)))
    ;; v1: all-zero cookie and nonces.
    (let ((z (make-array 32 :element-type '(unsigned-byte 8) :initial-element 0)))
      (is (equalp (%hx "3d1188024fd00a2a157e9850572bb3b26af8c149d2d21838c7bccc7fa83a8574")
                  (server z z z)))
      (is (equalp (%hx "e219bbb6012dd83bb787c2b3462ad9cacd2636ea51e2c708e8c0758d27bddc21")
                  (client z z z))))
    ;; v2: patterned bytes.
    (let ((cookie (%hx "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
          (cn (%hx "01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3da"))
          (sn (%hx "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2")))
      (is (equalp (%hx "bedf5eba8867f45e7c133e3014749bc08e1b358d586b6884036af3c7aeba6f00")
                  (server cookie cn sn)))
      (is (equalp (%hx "7127b9b6012af2706770702b1a65846ee066d92cf11194fb15ee9c220c7d9cb4")
                  (client cookie cn sn))))
    ;; v3: 0xA5 cookie, sha256-derived nonces.
    (let ((cookie (%hx "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"))
          (cn (%hx "948fe603f61dc036b5c596dc09fe3ce3f3d30dc90f024c85f3c82db2ccab679d"))
          (sn (%hx "b3eacd33433b31b5252351032c9b3e7a2e7aa7738d5decdf0dd6c62680853c06")))
      (is (equalp (%hx "da2b75f6afb1cbc2c211a393ff52cce626c03d66d5fa1a3f9f224172fdce6a81")
                  (server cookie cn sn)))
      (is (equalp (%hx "2cd2d296777675871179f9d5a308e243f6aa77800677bac357b2d2d199ba1d70")
                  (client cookie cn sn))))))

;;; --- command formatting / spec parsing ---------------------------------------

(test tor-add-onion-command-format
  "ADD_ONION command: NEW:ED25519-V3 on first run, the cached key verbatim on
restore; virtual port = chain default, forwarding to the local onion listener
(torcontrol.cpp:476-481)."
  (let ((ctl (bl.net::make-tor-controller
              :virtual-port 8333 :target-host "127.0.0.1" :target-port 8334)))
    (is (string= "ADD_ONION NEW:ED25519-V3 Port=8333,127.0.0.1:8334"
                 (bl.net::tor-add-onion-command ctl)))
    (setf (bl.net::tor-controller-private-key ctl)
          "ED25519-V3:SGVsbG8=")
    (is (string= "ADD_ONION ED25519-V3:SGVsbG8= Port=8333,127.0.0.1:8334"
                 (bl.net::tor-add-onion-command ctl)))))

(test tor-parse-torcontrol-spec
  "-torcontrol host[:port] parsing; port defaults to 9051."
  (flet ((check (spec host port)
           (multiple-value-bind (h p)
               (bl.net:parse-torcontrol-spec spec)
             (is (string= host h) "host of ~S" spec)
             (is (= port p) "port of ~S" spec))))
    (check nil "127.0.0.1" 9051)
    (check "" "127.0.0.1" 9051)
    (check "127.0.0.1" "127.0.0.1" 9051)
    (check "127.0.0.1:9151" "127.0.0.1" 9151)
    (check "10.0.0.2:19051" "10.0.0.2" 19051)
    (check "[::1]" "::1" 9051)
    (check "[::1]:9151" "::1" 9151)
    (check "::1" "::1" 9051)))         ; bare IPv6: host-only

;;; --- private key persistence -------------------------------------------------

(test tor-onion-key-persistence-roundtrip
  "The service key round-trips through onion_v3_private_key verbatim and the
file is owner-only (0600). Core stores the exact PrivateKey reply value."
  (let* ((dir (%torcontrol-temp-dir))
         (path (merge-pathnames "onion_v3_private_key" dir))
         (key "ED25519-V3:yLSDc8b11PaIHTtNtvi9lNzZQMR3XVRBE5q3BSc1JBWidunZLxSFhsP2CIkjT5oJ58rPYYNjSCkQnLtzfFPqfA=="))
    (unwind-protect
         (progn
           (is-true (bl.net::write-onion-private-key path key))
           (is (string= key (bl.net::read-onion-private-key path)))
           ;; Owner-only permissions.
           #+sbcl
           (is (= #o600 (logand (sb-posix:stat-mode
                                 (sb-posix:stat (namestring path)))
                                #o777)))
           ;; A trailing newline (hand-edited file) is trimmed on read.
           (with-open-file (out path :direction :output :if-exists :supersede)
             (write-string key out)
             (terpri out))
           (is (string= key (bl.net::read-onion-private-key path))))
      (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))))

;;; --- local addresses + advertisement policy ----------------------------------

(defparameter +test-onion-pubkey+
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 7)
  "A fixed 32-byte ed25519 pubkey for onion local-address tests.")

(test tor-add-local-gates
  "add-local (Core AddLocal): refuses scores below LOCAL_MANUAL (no discovery
support), unreachable networks (e.g. onion without a Tor route), and
unroutable bytes; a re-add with >= score bumps the score by one."
  (with-tor-globals
    ;; :torv3 not reachable -> refused.
    (is-false (bl.net:add-local
               :torv3 +test-onion-pubkey+ 8333
               bl.net:+local-manual+))
    (push :torv3 bl.net:*reachable-networks*)
    ;; Score below LOCAL_MANUAL -> refused (fDiscover is permanently false).
    (is-false (bl.net:add-local :torv3 +test-onion-pubkey+ 8333 0))
    ;; All-zero bytes are unroutable.
    (is-false (bl.net:add-local
               :torv3 (make-array 32 :element-type '(unsigned-byte 8)
                                     :initial-element 0)
               8333 bl.net:+local-manual+))
    (is-true (bl.net:add-local
              :torv3 +test-onion-pubkey+ 8333
              bl.net:+local-manual+))
    (is (= 1 (length (bl.net:local-addresses))))
    (let ((la (first (bl.net:local-addresses))))
      (is (= bl.net:+local-manual+
             (bl.net:local-address-score la))))
    ;; Re-add with equal score: score+1, port updated, still one entry.
    (is-true (bl.net:add-local
              :torv3 +test-onion-pubkey+ 18333
              bl.net:+local-manual+))
    (is (= 1 (length (bl.net:local-addresses))))
    (let ((la (first (bl.net:local-addresses))))
      (is (= (1+ bl.net:+local-manual+)
             (bl.net:local-address-score la)))
      (is (= 18333 (bl.net:local-address-port la))))
    ;; remove-local is keyed by address only.
    (bl.net:remove-local :torv3 +test-onion-pubkey+)
    (is (null (bl.net:local-addresses)))))

(test tor-best-local-address-privacy-rule
  "GetLocal's privacy rule (net.cpp:174-186): a privacy-net (onion) local
address is only advertised to peers connected through that same network, and
privacy-net peers are never told our other-network addresses."
  (with-tor-globals
    (push :torv3 bl.net:*reachable-networks*)
    (bl.net:add-local
     :torv3 +test-onion-pubkey+ 8333 bl.net:+local-manual+)
    ;; Onion-connected peer: gets the onion address.
    (let ((la (bl.net:best-local-address :torv3)))
      (is-true la)
      (is (eq :torv3 (bl.net:local-address-network la))))
    ;; Clearnet peers: never told the onion address.
    (is-false (bl.net:best-local-address :ipv4))
    (is-false (bl.net:best-local-address :ipv6))
    (is-false (bl.net:best-local-address :unroutable))
    ;; Add a clearnet local address too: clearnet peers get it, and the
    ;; onion-connected peer still only ever sees the onion one.
    (bl.net:add-local
     :ipv4 (bl.net:ipv4-to-mapped-ipv6 1 2 3 4) 8333
     bl.net:+local-manual+)
    (let ((la (bl.net:best-local-address :ipv4)))
      (is-true la)
      (is (eq :ipv4 (bl.net:local-address-network la))))
    (let ((la (bl.net:best-local-address :torv3)))
      (is-true la)
      (is (eq :torv3 (bl.net:local-address-network la))))))

(test tor-peer-connected-through-network
  "ConnectedThroughNetwork: inbound-onion peers are :torv3 regardless of
socket address; others follow their address; hostnames are :unroutable."
  (let ((onion-peer (bl.net:make-peer
                     :address "127.0.0.1" :inbound t :inbound-onion t))
        (v4-peer (bl.net:make-peer :address "8.8.8.8"))
        (onion-out (bl.net:make-peer
                    :address (bl.net:onion-address-string
                              +test-onion-pubkey+)))
        (host-peer (bl.net:make-peer :address "seed.example.com")))
    (is (eq :torv3 (bl.net:peer-connected-through-network onion-peer)))
    (is (eq :ipv4 (bl.net:peer-connected-through-network v4-peer)))
    (is (eq :torv3 (bl.net:peer-connected-through-network onion-out)))
    (is (eq :unroutable (bl.net:peer-connected-through-network host-peer)))))

(test tor-self-advertisement-message-construction
  "The self-announcement for our onion address is an addrv2 message carrying
the torv3 entry with our services; a peer without sendaddrv2 gets nothing
(Core IsAddrCompatible — torv3 is not V1-representable)."
  (with-tor-globals
    (push :torv3 bl.net:*reachable-networks*)
    (bl.net:add-local
     :torv3 +test-onion-pubkey+ 48333 bl.net:+local-manual+)
    (let* ((peer (bl.net:make-peer
                  :address "127.0.0.1" :inbound t :inbound-onion t))
           (la (bl.net:get-local-addr-for-peer peer)))
      (is-true la)
      ;; No addrv2 negotiated: nothing to send.
      (let ((pa (bl.net:make-peer-address
                 :net (bl.net:local-address-network la)
                 :ip (bl.net:local-address-bytes la)
                 :port (bl.net:local-address-port la)
                 :services (bl.net:local-services)
                 :last-seen (bl.ser:get-unix-time))))
        (is-false (bl.net::build-addr-response peer (list pa)))
        ;; With addrv2: a single-entry addrv2 message with our torv3 address.
        (setf (bl.net:peer-wants-addrv2 peer) t)
        (let ((msg (bl.net::build-addr-response peer (list pa))))
          (is-true msg)
          ;; Parse the payload back (skip the 24-byte P2P header).
          (let* ((payload (subseq msg 24))
                 (entries (bl.ser:parse-addrv2-payload payload)))
            (is (= 1 (length entries)))
            (destructuring-bind (net-addr timestamp network-id) (first entries)
              (declare (ignore timestamp))
              (is (= 4 network-id))     ; BIP155 TORV3
              (is (equalp +test-onion-pubkey+
                          (bl.ser:net-addr-ip net-addr)))
              (is (= 48333 (bl.ser:net-addr-port net-addr)))
              (is (= (bl.net:local-services)
                     (bl.ser:net-addr-services net-addr))))))))
    ;; A clearnet peer gets no local address at all (privacy rule).
    (let ((clearnet (bl.net:make-peer :address "8.8.8.8")))
      (is-false (bl.net:get-local-addr-for-peer clearnet)))))

(test tor-version-addr-recv
  "The version message's addr_recv carries the peer's own routable address
(Core PushNodeVersion's addr_you); non-IP and hostname peers get the all-zero
dummy; addr_from is always the all-zero dummy, exactly like modern Core."
  (let ((v4-peer (bl.net:make-peer
                  :address "8.8.8.8"
                  :connection (bl.net::make-connection
                               :host "8.8.8.8" :port 8333))))
    (setf (bl.net:peer-services v4-peer) 1033)
    (let ((na (bl.net::%version-addr-recv v4-peer)))
      (is (equalp (bl.net:ipv4-to-mapped-ipv6 8 8 8 8)
                  (bl.ser:net-addr-ip na)))
      (is (= 8333 (bl.ser:net-addr-port na)))
      (is (= 1033 (bl.ser:net-addr-services na)))))
  ;; Onion peer: not V1-compatible -> dummy.
  (let* ((onion-peer (bl.net:make-peer
                      :address (bl.net:onion-address-string
                                +test-onion-pubkey+)))
         (na (bl.net::%version-addr-recv onion-peer)))
    (is (every #'zerop (bl.ser:net-addr-ip na)))
    (is (zerop (bl.ser:net-addr-port na))))
  ;; Hostname peer: unparseable -> dummy.
  (let* ((host-peer (bl.net:make-peer :address "node.example.com"))
         (na (bl.net::%version-addr-recv host-peer)))
    (is (every #'zerop (bl.ser:net-addr-ip na))))
  ;; Full round-trip: the serialized version message carries addr_recv and a
  ;; zero addr_from.
  (let* ((recv (bl.ser:make-net-addr
                :services 9
                :ip (bl.net:ipv4-to-mapped-ipv6 1 2 3 4)
                :port 8333))
         (bytes (bl.ser:make-version-message-bytes
                 :services 1033 :addr-recv recv))
         (msg (bl.bytes:with-byte-reader (s bytes)
                (bl.ser:read-version-message s))))
    (is (equalp (bl.net:ipv4-to-mapped-ipv6 1 2 3 4)
                (bl.ser:net-addr-ip
                 (bl.ser:version-message-addr-recv msg))))
    (is (= 8333 (bl.ser:net-addr-port
                 (bl.ser:version-message-addr-recv msg))))
    (is (every #'zerop (bl.ser:net-addr-ip
                        (bl.ser::version-message-addr-from msg))))
    (is (zerop (bl.ser:net-addr-port
                (bl.ser::version-message-addr-from msg))))))

;;; --- config wiring -----------------------------------------------------------

(test tor-config-options
  "-torcontrol/-torpassword/-listenonion wire through to start-node keywords;
-listen=0 soft-disables -listenonion (init.cpp:808) and the explicit
combination -listen=0 -listenonion=1 is an init error (init.cpp:1022-1024);
-proxy's listen soft-off cascades to listenonion."
  (let ((plist (start-node-plist
                '("-torcontrol=127.0.0.1:9151" "-torpassword=hunter2"))))
    (is (string= "127.0.0.1:9151" (getf plist :tor-control)))
    (is (string= "hunter2" (getf plist :tor-password)))
    ;; Default: listenonion not forced off (absent -> start-node default T).
    (is (eq 'unset (getf plist :listen-onion 'unset))))
  (let ((plist (start-node-plist '("-listen=0"))))
    (is (null (getf plist :listen)))
    (is (null (getf plist :listen-onion 'unset))))
  (let ((plist (start-node-plist '("-proxy=127.0.0.1:9050"))))
    (is (null (getf plist :listen)))
    (is (null (getf plist :listen-onion 'unset))))
  (signals error
    (start-node-plist '("-listen=0" "-listenonion=1")))
  (signals error
    (start-node-plist '("-proxy=127.0.0.1:9050" "-listenonion")))
  ;; Explicit listen=1 with listenonion stays on.
  (let ((plist (start-node-plist '("-listen=1" "-listenonion=1"))))
    (is (eq t (getf plist :listen-onion)))))

(test tor-config-onion-explicit-and-onlynet
  "apply-config-globals records whether -onion was given at all (the GETINFO
auto-configure gate) and keeps the raw -onlynet list; -onlynet=onion without
any Tor route errors, but is allowed when -listenonion will deliver one
(init.cpp:1788-1798)."
  (with-tor-globals
    (let ((old-datacarrier bl:*accept-datacarrier*))
      (unwind-protect
           (progn
             ;; No -onion: not explicit.
             (bl::apply-config-globals '())
             (is-false bl.net:*onion-proxy-explicit*)
             (is (null bl.net:*onlynet-networks*))
             ;; -onion given: explicit, proxy set.
             (bl::apply-config-globals '(("onion" . "127.0.0.1:9050")))
             (is-true bl.net:*onion-proxy-explicit*)
             (is-true bl.net:*onion-proxy*)
             ;; -onion=0: explicit, proxy cleared.
             (setf bl.net:*onion-proxy* nil)
             (bl::apply-config-globals '(("onion" . "0")))
             (is-true bl.net:*onion-proxy-explicit*)
             (is (null bl.net:*onion-proxy*))
             ;; -onlynet=onion with no proxy and listenonion off -> error.
             (setf bl.net:*onion-proxy* nil)
             (signals error
               (bl::apply-config-globals
                '(("onlynet" . "onion") ("listenonion" . "0"))))
             ;; -onlynet=onion + -onion=0 -> error even with listenonion.
             (signals error
               (bl::apply-config-globals
                '(("onlynet" . "onion") ("onion" . "0"))))
             ;; -onlynet=onion with default listenonion -> allowed; :torv3
             ;; stays out of the reachable set until torcontrol delivers the
             ;; proxy (Core get_socks_cb re-adds it).
             (bl::apply-config-globals '(("onlynet" . "onion")))
             (is (equal '(:torv3) bl.net:*onlynet-networks*))
             (is (not (member :torv3 bl.net:*reachable-networks*))))
        (setf bl:*accept-datacarrier* old-datacarrier)))))

;;; --- end-to-end against a fake control server --------------------------------

(test torcontrol-e2e-null-auth-new-service
  "Full flow against a fake control port: PROTOCOLINFO -> NULL auth ->
GETINFO net/listeners/socks (auto-configures the onion proxy + reachability,
-onion unset) -> ADD_ONION NEW:ED25519-V3 -> ServiceID/PrivateKey parsed, key
persisted 0600, .onion address AddLocal'd."
  (with-tor-globals
    (let* ((dir (%torcontrol-temp-dir))
           (onion (bl.net:onion-address-string +test-onion-pubkey+))
           (service-id (subseq onion 0 56))
           (key "ED25519-V3:c2VjcmV0a2V5YmxvYg=="))
      (multiple-value-bind (port thread received)
          (%fake-tor-server
           (lambda (line)
             (cond
               ((uiop:string-prefix-p "PROTOCOLINFO" line)
                '("250-PROTOCOLINFO 1"
                  "250-AUTH METHODS=NULL,SAFECOOKIE COOKIEFILE=\"/nonexistent\""
                  "250-VERSION Tor=\"0.4.8.12\""
                  "250 OK"))
               ((string= line "AUTHENTICATE") '("250 OK"))
               ((uiop:string-prefix-p "GETINFO" line)
                '("250-net/listeners/socks=\"127.0.0.1:19050\"" "250 OK"))
               ((uiop:string-prefix-p "ADD_ONION" line)
                (list (format nil "250-ServiceID=~A" service-id)
                      (format nil "250-PrivateKey=~A" key)
                      "250 OK")))))
        (let ((ctl (bl.net:start-tor-control
                    :control-spec (format nil "127.0.0.1:~D" port)
                    :data-directory dir
                    :virtual-port 48333
                    :target-port 48334)))
          (unwind-protect
               (progn
                 (is-true (%wait-until
                           (lambda ()
                             (bl.net::tor-controller-service-pubkey ctl))))
                 (is (string= service-id
                              (bl.net:tor-controller-service-id ctl)))
                 ;; ADD_ONION command formatting on the wire.
                 (is-true (member "ADD_ONION NEW:ED25519-V3 Port=48333,127.0.0.1:48334"
                                  (funcall received) :test #'string=))
                 ;; Onion proxy auto-configured from GETINFO (-onion unset).
                 (is-true bl.net:*onion-proxy*)
                 (is (string= "127.0.0.1"
                              (bl.net:proxy-host
                               bl.net:*onion-proxy*)))
                 (is (= 19050 (bl.net:proxy-port
                               bl.net:*onion-proxy*)))
                 (is-true (member :torv3 bl.net:*reachable-networks*))
                 ;; Local address registered at LOCAL_MANUAL with the chain port.
                 (let ((locals (bl.net:local-addresses)))
                   (is (= 1 (length locals)))
                   (let ((la (first locals)))
                     (is (eq :torv3 (bl.net:local-address-network la)))
                     (is (equalp +test-onion-pubkey+
                                 (bl.net:local-address-bytes la)))
                     (is (= 48333 (bl.net:local-address-port la)))
                     (is (= bl.net:+local-manual+
                            (bl.net:local-address-score la)))))
                 ;; Key persisted verbatim, owner-only.
                 (let ((path (merge-pathnames "onion_v3_private_key" dir)))
                   (is (string= key (bl.net::read-onion-private-key path)))
                   #+sbcl
                   (is (= #o600 (logand (sb-posix:stat-mode
                                         (sb-posix:stat (namestring path)))
                                        #o777)))))
            (bl.net:stop-tor-control ctl)
            (ignore-errors (bt:join-thread thread))
            (uiop:delete-directory-tree dir :validate t :if-does-not-exist :ignore))))
      ;; stop-tor-control unregistered the service (Core ~TorController).
      (is (null (bl.net:local-addresses))))))

(test torcontrol-e2e-safecookie-and-key-restore
  "SAFECOOKIE auth end-to-end: the client reads the cookie file, sends
AUTHCHALLENGE with a fresh nonce, verifies the server's HMAC proof, and
answers with the controller-to-server HMAC (verified by the server); a
cached onion key is sent verbatim in ADD_ONION and survives a reply that
carries no PrivateKey (restore path)."
  (with-tor-globals
    ;; Simulate '-onion given': skip GETINFO, onion reachable from startup.
    (setf bl.net:*onion-proxy-explicit* t)
    (push :torv3 bl.net:*reachable-networks*)
    (let* ((dir (%torcontrol-temp-dir))
           (onion (bl.net:onion-address-string +test-onion-pubkey+))
           (service-id (subseq onion 0 56))
           (saved-key "ED25519-V3:cmVzdG9yZWRrZXk=")
           (cookie (bl.crypto:hex-to-bytes
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
           (cookie-path (merge-pathnames "control_auth_cookie" dir))
           (server-nonce (bl.crypto:hex-to-bytes
                          "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2"))
           (client-nonce nil)
           (auth-ok nil))
      ;; Seed the cookie + cached key files.
      (with-open-file (out cookie-path :direction :output
                                       :element-type '(unsigned-byte 8))
        (write-sequence cookie out))
      (bl.net::write-onion-private-key
       (merge-pathnames "onion_v3_private_key" dir) saved-key)
      (multiple-value-bind (port thread received)
          (%fake-tor-server
           (lambda (line)
             (cond
               ((uiop:string-prefix-p "PROTOCOLINFO" line)
                (list "250-PROTOCOLINFO 1"
                      (format nil "250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"~A\""
                              (namestring cookie-path))
                      "250 OK"))
               ((uiop:string-prefix-p "AUTHCHALLENGE SAFECOOKIE " line)
                (setf client-nonce (bl.crypto:hex-to-bytes
                                    (subseq line (length "AUTHCHALLENGE SAFECOOKIE "))))
                (list (format nil "250 AUTHCHALLENGE SERVERHASH=~A SERVERNONCE=~A"
                              (bl.crypto:bytes-to-hex
                               (bl.net::compute-safecookie-response
                                bl.net::+tor-safe-serverkey+
                                cookie client-nonce server-nonce))
                              (bl.crypto:bytes-to-hex server-nonce))))
               ((uiop:string-prefix-p "AUTHENTICATE " line)
                (let ((expected (bl.crypto:bytes-to-hex
                                 (bl.net::compute-safecookie-response
                                  bl.net::+tor-safe-clientkey+
                                  cookie client-nonce server-nonce))))
                  (if (string-equal expected (subseq line (length "AUTHENTICATE ")))
                      (progn (setf auth-ok t) '("250 OK"))
                      '("515 Authentication failed"))))
               ((uiop:string-prefix-p "ADD_ONION" line)
                ;; Restore path: ServiceID only, no PrivateKey line.
                (list (format nil "250-ServiceID=~A" service-id) "250 OK")))))
        (let ((ctl (bl.net:start-tor-control
                    :control-spec (format nil "127.0.0.1:~D" port)
                    :data-directory dir
                    :virtual-port 8333
                    :target-port 8334)))
          (unwind-protect
               (progn
                 (is-true (%wait-until
                           (lambda ()
                             (bl.net::tor-controller-service-pubkey ctl))))
                 (is-true auth-ok)      ; server verified our HMAC
                 (is (= 32 (length client-nonce)))
                 ;; The cached key went out verbatim.
                 (is-true (member (format nil "ADD_ONION ~A Port=8333,127.0.0.1:8334"
                                          saved-key)
                                  (funcall received) :test #'string=))
                 ;; No GETINFO: -onion was explicitly configured.
                 (is-false (find-if (lambda (l) (uiop:string-prefix-p "GETINFO" l))
                                    (funcall received)))
                 ;; Key file untouched by the PrivateKey-less reply.
                 (is (string= saved-key
                              (bl.net::read-onion-private-key
                               (merge-pathnames "onion_v3_private_key" dir))))
                 (is (= 1 (length (bl.net:local-addresses)))))
            (bl.net:stop-tor-control ctl)
            (ignore-errors (bt:join-thread thread))
            (uiop:delete-directory-tree dir :validate t
                                            :if-does-not-exist :ignore)))))))

(test torcontrol-e2e-add-onion-error
  "A 551 (key failure) ADD_ONION reply is logged and leaves no service and no
local address; the control connection stays up (Core add_onion_cb error arm —
no retry, no disconnect)."
  (with-tor-globals
    (setf bl.net:*onion-proxy-explicit* t)
    (push :torv3 bl.net:*reachable-networks*)
    (let ((dir (%torcontrol-temp-dir))
          (add-onion-seen nil))
      (multiple-value-bind (port thread received)
          (%fake-tor-server
           (lambda (line)
             (cond
               ((uiop:string-prefix-p "PROTOCOLINFO" line)
                '("250-PROTOCOLINFO 1" "250-AUTH METHODS=NULL" "250 OK"))
               ((string= line "AUTHENTICATE") '("250 OK"))
               ((uiop:string-prefix-p "ADD_ONION" line)
                (setf add-onion-seen t)
                '("551 Failed to generate onion address")))))
        (declare (ignore received))
        (let ((ctl (bl.net:start-tor-control
                    :control-spec (format nil "127.0.0.1:~D" port)
                    :data-directory dir
                    :virtual-port 8333
                    :target-port 8334)))
          (unwind-protect
               (progn
                 (is-true (%wait-until (lambda () add-onion-seen)))
                 (sleep 0.3)            ; let the (non-)registration settle
                 (is (null (bl.net:tor-controller-service-id ctl)))
                 (is (null (bl.net:local-addresses)))
                 ;; Connection held open: thread alive, not reconnect-looping.
                 (is-true (bt:thread-alive-p
                           (bl.net::tor-controller-thread ctl))))
            (bl.net:stop-tor-control ctl)
            (ignore-errors (bt:join-thread thread))
            (uiop:delete-directory-tree dir :validate t
                                            :if-does-not-exist :ignore)))))))

;;;; ============================================================
;;;; Self-announcement of our own local address (Core MaybeSendAddr's
;;;; local half). It lives here because the local-address map is this
;;;; file's fixture.
;;;; ============================================================

(defun %local-addr-deadline (peer)
  "PEER's next self-announcement deadline (Core Peer::m_next_local_addr_send;
0 = never announced). SETF-able so a test can make a peer due again without
waiting out an exponential draw."
  (bl.net::peer-next-local-addr-send peer))

(defun (setf %local-addr-deadline) (ticks peer)
  (setf (bl.net::peer-next-local-addr-send peer) ticks))

(test self-announcement-is-alone-once-then-rides-the-gossip-queue
  "Core sends only the FIRST self-announcement as its own message -- its
comment: \"this makes sure rate-limiting with limited start-tokens doesn't
ignore it if the first message ends up containing multiple addresses\" -- and
PushAddress's every later one onto the peer's ordinary gossip queue, having
first reset that peer's addr-known filter so the queue's own filter cannot
drop the repeat (net_processing.cpp:5537-5566).

Ours sent every announcement as its own message and marked the address known.
Each repeat was therefore a lone addr arriving exactly when our 24h timer
fired -- the correlation the batched flush exists to destroy -- and the mark
was never lifted, so our address could never have ridden the queue at all."
  (with-tor-globals
    ;; Core gates the self-announcement on !IsInitialBlockDownload; the latch
    ;; is already off here so the pass reaches the announcement at all.
    (let ((bl.net::*cached-is-ibd* nil)
          (ip (bl.net:ipv4-to-mapped-ipv6 1 2 3 4)))
      (bl.net:add-local :ipv4 ip 8333 bl.net:+local-manual+)
      (let ((peer (bl.net:make-peer :state :ready :addr-relay-enabled t
                                    :address "192.0.2.70:8333")))
        (%with-captured-sends (sends)
          ;; First: its own single-address message, nothing queued.
          (is (= 1 (bl.net:maybe-advertise-local-address (list peer) nil)))
          (is (= 1 (length sends))
              "the first self-announcement is its own message")
          (is (= 0 (length (%addr-queue peer)))
              "and does not go through the gossip queue")
          (is (plusp (%local-addr-deadline peer)) "the ~24h timer is armed")
          ;; Due again: the repeat is QUEUED, not sent.
          (setf (%local-addr-deadline peer) 1)
          (is (= 1 (bl.net:maybe-advertise-local-address (list peer) nil)))
          (is (= 1 (length sends)) "a repeat puts nothing on the wire of its own")
          (is (= 1 (length (%addr-queue peer)))
              "it waits in the gossip queue with everything else")
          ;; And the repeat survives the queue's own known-address filter,
          ;; which is what the reset is for: mark our address known (what a
          ;; flush of the previous one does) and it must still be queued.
          (setf (fill-pointer (%addr-queue peer)) 0)
          (bl:add-recent-reject
           (bl.net:peer-known-addrs peer)
           (bl.net::%addr-gossip-key
            (bl.net:make-peer-address :net :ipv4 :ip ip :port 8333)))
          (setf (%local-addr-deadline peer) 1)
          (is (= 1 (bl.net:maybe-advertise-local-address (list peer) nil)))
          (is (= 1 (length (%addr-queue peer)))
              "the addr-known filter is reset first, so a peer that already ~
               knows our address is still told again"))))))
