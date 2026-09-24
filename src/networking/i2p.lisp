(in-package #:bitcoin-lisp.networking)

;;;; I2P through a SAM 3.1 bridge (Bitcoin Core i2p.{h,cpp}).
;;;
;;; -i2psam names the router's SAM port. A SESSION is a control connection
;;; that stays open for its life (SESSION CREATE ... ID=<id>); each stream is
;;; a fresh connection that says HELLO and then STREAM CONNECT (outbound) or
;;; STREAM ACCEPT (inbound) with that id, after which the socket carries the
;;; peer's bytes. A PERSISTENT session (-i2pacceptincoming, the default) keeps
;;; its destination in <datadir>/i2p_private_key so the node's .b32.i2p
;;; address survives restarts and inbound peers can reach it; without it every
;;; outbound dial uses a TRANSIENT session whose destination the router makes
;;; up. SAM 3.1 has no ports: an I2P address is always port 0
;;; (I2P_SAM31_PORT), and a dial to any other port is refused.
;;;
;;; Line protocol: one request per line, one reply per line, `KEY=VALUE'
;;; words. I2P's Base64 swaps `+/' for `-~'.

(defconstant +i2p-sam31-port+ 0 "Core I2P_SAM31_PORT (i2p.h).")
(defconstant +i2p-max-msg-size+ 65536 "Core i2p::sam::MAX_MSG_SIZE (i2p.h).")
(defconstant +i2p-reply-timeout-seconds+ 180
  "Core's recv_timeout in SendRequestAndGetReply (i2p.cpp:307): a name lookup
can keep the router busy for minutes.")
(defconstant +i2p-max-wait-for-io-seconds+ 1
  "Core MAX_WAIT_FOR_IO (i2p.h): the accept loop's wait between interrupt checks.")
(defconstant +max-unused-i2p-sessions+ 10
  "Core MAX_UNUSED_I2P_SESSIONS_SIZE (net.h): transient sessions kept for reuse
after a failed dial.")

(define-condition i2p-error (error)
  ((message :initarg :message :reader i2p-error-message))
  (:report (lambda (c s) (write-string (i2p-error-message c) s)))
  (:documentation "Core's std::runtime_error inside i2p::sam::Session."))

(defun %i2p-fail (control &rest args)
  (error 'i2p-error :message (apply #'format nil control args)))

(defun %i2p-swap-base64 (string)
  "Core SwapBase64 (i2p.cpp:43-66): standard <-> I2P Base64."
  (map 'string (lambda (c) (case c (#\- #\+) (#\~ #\/) (#\+ #\-) (#\/ #\~) (t c))) string))

(defun %i2p-decode-base64 (string)
  "Core DecodeI2PBase64 (i2p.cpp:74-82)."
  (or (bl.ser:decode-base64 (%i2p-swap-base64 string))
      (%i2p-fail "Cannot decode Base64: \"~A\"" string)))

(defun i2p-destination-address (destination)
  "Core DestBinToAddr (i2p.cpp:90-104): a binary DESTINATION's .b32.i2p name,
base32 of its SHA256."
  (i2p-address-string (ironclad:digest-sequence :sha256 destination)))

(defstruct (i2p-session (:constructor %make-i2p-session))
  "Core i2p::sam::Session."
  (control-host "" :type string)        ; -i2psam as Proxy::ToString prints it
  (private-key-file nil)                ; NIL: a transient session
  (control-sock nil)                    ; the open SESSION CREATE connection
  (session-id "" :type string)
  (my-addr nil)                         ; "<name>.b32.i2p:0" once created
  (private-key nil)
  (lock (bt:make-recursive-lock "i2p-session")))

(defun make-i2p-session (control-host &optional private-key-file)
  "A session on the SAM bridge CONTROL-HOST (\"host:port\"): persistent,
keeping its destination in PRIVATE-KEY-FILE, or transient without one."
  (%make-i2p-session :control-host control-host :private-key-file private-key-file))

(defun i2p-session-transient-p (session)
  (null (i2p-session-private-key-file session)))

;;; --- The line protocol ---

(defun %i2p-send-line (sock line)
  (let ((stream (usocket:socket-stream sock)))
    (write-sequence (map '(vector (unsigned-byte 8)) #'char-code line) stream)
    (write-byte 10 stream)
    (force-output stream)))

(defun %i2p-recv-line (sock timeout)
  "Core Sock::RecvUntilTerminator('\\n', TIMEOUT, ..., MAX_MSG_SIZE): the
line without its terminator."
  (let ((stream (usocket:socket-stream sock))
        (deadline (+ (get-internal-real-time) (* timeout internal-time-units-per-second)))
        (out (make-string-output-stream))
        (n 0))
    (loop
      (unless (or (listen stream)
                  (socket-input-ready-p sock :timeout (max 0 (/ (- deadline (get-internal-real-time))
                                                              internal-time-units-per-second))))
        (%i2p-fail "Receive timeout (received ~D bytes without terminator before that)" n))
      (let ((b (read-byte stream nil nil)))
        (cond ((null b) (%i2p-fail "Connection unexpectedly closed by peer"))
              ((= b 10) (return (get-output-stream-string out)))
              (t (write-char (code-char b) out)
                 (when (> (incf n) +i2p-max-msg-size+)
                   (%i2p-fail "Received too many bytes without a terminator (~D)" n))))))))

(defun %i2p-request (sock request &key (check-ok t))
  "Core SendRequestAndGetReply (i2p.cpp:294-332): send REQUEST, read the reply
line, and return (VALUES keys full) -- KEYS an alist of KEY to value, or to
NIL for a word without `='. With CHECK-OK a RESULT other than OK is an error.
A SESSION CREATE request is logged as `SESSION CREATE ...': it carries our
private key."
  (%i2p-send-line sock request)
  (let* ((shown (if (uiop:string-prefix-p "SESSION CREATE" request) "SESSION CREATE ..." request))
         (full (%i2p-recv-line sock +i2p-reply-timeout-seconds+))
         (keys (loop for word in (uiop:split-string full :separator " ")
                     for eq = (position #\= word)
                     collect (if eq (cons (subseq word 0 eq) (subseq word (1+ eq))) (cons word nil)))))
    (when (and check-ok (not (equal "OK" (%i2p-reply-get keys "RESULT" shown full))))
      (%i2p-fail "Unexpected reply to \"~A\": \"~A\"" request full))
    (values keys full shown)))

(defun %i2p-reply-get (keys key request full)
  "Core Session::Reply::Get (i2p.cpp:283-292)."
  (let ((cell (assoc key keys :test #'string=)))
    (or (cdr cell)
        (%i2p-fail "Missing ~A= in the reply to \"~A\": \"~A\"" key request full))))

(defun %i2p-get (sock request key &key (check-ok t))
  "Send REQUEST and return the reply's KEY."
  (multiple-value-bind (keys full shown) (%i2p-request sock request :check-ok check-ok)
    (values (%i2p-reply-get keys key shown full) full)))

(defun %i2p-hello (session)
  "Core Session::Hello (i2p.cpp:334-345): a new connection to the bridge that
has agreed on SAM 3.1."
  (let* ((host (i2p-session-control-host session))
         (sock (multiple-value-bind (h p) (split-host-port host 7656)
                 (ignore-errors (%socket-connect h p 10)))))
    (unless sock
      (%i2p-fail "Cannot connect to ~A" host))
    (handler-bind ((error (lambda (e) (declare (ignore e)) (ignore-errors (usocket:socket-close sock)))))
      (%i2p-request sock "HELLO VERSION MIN=3.1 MAX=3.1"))
    sock))

;;; --- The session ---

(defun %i2p-control-sock-alive-p (session)
  "Core Sock::IsConnected on the control socket: open, and not at end of file."
  (let ((sock (i2p-session-control-sock session)))
    (and sock
         (handler-case
             (let ((stream (usocket:socket-stream sock)))
               (or (not (socket-input-ready-p sock :timeout 0))
                   (and (listen stream) t)
                   ;; Readable with nothing buffered: EOF or an error.
                   nil))
           (error () nil)))))

(defun i2p-session-disconnect (session)
  "Core Session::Disconnect (i2p.cpp:477-491)."
  (bt:with-recursive-lock-held ((i2p-session-lock session))
    (when (i2p-session-control-sock session)
      (if (string= "" (i2p-session-session-id session))
          (bl.log:log-info "Destroying incomplete I2P SAM session")
          (bl.log:log-info "Destroying I2P SAM session ~A" (i2p-session-session-id session)))
      (ignore-errors (usocket:socket-close (i2p-session-control-sock session)))
      (setf (i2p-session-control-sock session) nil))
    (setf (i2p-session-session-id session) "")))

(defun %i2p-check-control-sock (session)
  "Core Session::CheckControlSock (i2p.cpp:347-357)."
  (bt:with-recursive-lock-held ((i2p-session-lock session))
    (when (and (i2p-session-control-sock session)
               (not (%i2p-control-sock-alive-p session)))
      (bl.log:log-cat "i2p" "Control socket error: Connection closed")
      (i2p-session-disconnect session))))

(defun %i2p-my-destination (private-key)
  "Core Session::MyDestination (i2p.cpp:376-406): the public destination at the
front of PRIVATE-KEY, 387 bytes plus the certificate length at 385-386."
  (when (< (length private-key) 387)
    (%i2p-fail "The private key is too short (~D < 387)" (length private-key)))
  (let* ((cert-len (logior (ash (aref private-key 385) 8) (aref private-key 386)))
         (len (+ 387 cert-len)))
    (when (> len (length private-key))
      (%i2p-fail "Certificate length (~D) designates that the private key should be ~D bytes, but it is only ~D bytes"
                 cert-len len (length private-key)))
    (subseq private-key 0 len)))

(defun %i2p-read-or-generate-key (session sock)
  "The persistent destination: read from the key file, or DEST GENERATE and
save it (Core GenerateAndSavePrivateKey, i2p.cpp:359-374)."
  (let ((file (i2p-session-private-key-file session)))
    (or (and (probe-file file)
             (alexandria:read-file-into-byte-vector file))
        (let ((key (%i2p-decode-base64
                    (%i2p-get sock "DEST GENERATE SIGNATURE_TYPE=7" "PRIV" :check-ok nil))))
          (handler-case
              (with-open-file (out file :direction :output :if-exists :supersede
                                        :element-type '(unsigned-byte 8))
                (write-sequence key out))
            (error ()
              (%i2p-fail "Cannot save I2P private key to \"~A\"" (namestring file))))
          key))))

(defun %i2p-create-if-not-created (session)
  "Core Session::CreateIfNotCreatedAlready (i2p.cpp:408-458)."
  (when (%i2p-control-sock-alive-p session)
    (return-from %i2p-create-if-not-created))
  (let* ((type (if (i2p-session-transient-p session) "transient" "persistent"))
         (id (subseq (format nil "~(~16,'0X~)" (bl.crypto:rand-u64)) 0 10)))
    (bl.log:log-cat "i2p" "Creating ~A I2P SAM session ~A with ~A"
                    type id (i2p-session-control-host session))
    (let ((sock (%i2p-hello session)))
      (handler-bind ((error (lambda (e) (declare (ignore e)) (ignore-errors (usocket:socket-close sock)))))
        (if (i2p-session-transient-p session)
            (setf (i2p-session-private-key session)
                  (%i2p-decode-base64
                   (%i2p-get sock (format nil "SESSION CREATE STYLE=STREAM ID=~A DESTINATION=TRANSIENT SIGNATURE_TYPE=7 i2cp.leaseSetEncType=4,0 inbound.quantity=1 outbound.quantity=1" id)
                             "DESTINATION")))
            (let ((key (%i2p-read-or-generate-key session sock)))
              (setf (i2p-session-private-key session) key)
              (%i2p-request sock (format nil "SESSION CREATE STYLE=STREAM ID=~A DESTINATION=~A i2cp.leaseSetEncType=4,0 inbound.quantity=3 outbound.quantity=3"
                                         id (%i2p-swap-base64 (bl.ser:encode-base64 key))))))
        (setf (i2p-session-my-addr session)
              (format nil "~A:~D" (i2p-destination-address
                                   (%i2p-my-destination (i2p-session-private-key session)))
                      +i2p-sam31-port+)
              (i2p-session-session-id session) id
              (i2p-session-control-sock session) sock)
        (bl.log:log-info "~:(~A~) I2P SAM session ~A created, my address=~A"
                         type id (i2p-session-my-addr session))))))

(defun i2p-session-connect (session host port)
  "Core Session::Connect (i2p.cpp:222-281): a stream to HOST (a .b32.i2p
name). Returns (VALUES socket proxy-error-p): the socket carries the peer's
bytes; PROXY-ERROR-P is Core's proxy_error -- NIL only for a refused port or
a peer the router could not reach, whose failure is the address's own."
  (unless (= port +i2p-sam31-port+)
    (bl.log:log-cat "i2p" "Error connecting to ~A:~D, connection refused due to arbitrary port ~D"
                    host port port)
    (return-from i2p-session-connect (values nil nil)))
  (let ((proxy-error t) (sock nil))
    (handler-case
        (let ((id nil))
          (bt:with-recursive-lock-held ((i2p-session-lock session))
            (%i2p-create-if-not-created session)
            (setf id (i2p-session-session-id session)
                  sock (%i2p-hello session)))
          (let* ((dest (%i2p-get sock (format nil "NAMING LOOKUP NAME=~A" host) "VALUE"))
                 (request (format nil "STREAM CONNECT ID=~A DESTINATION=~A SILENT=false" id dest)))
            (multiple-value-bind (keys full shown) (%i2p-request sock request :check-ok nil)
              (let ((result (%i2p-reply-get keys "RESULT" shown full)))
                (cond ((string= result "OK")
                       (return-from i2p-session-connect (values (shiftf sock nil) nil)))
                      ((string= result "INVALID_ID")
                       (i2p-session-disconnect session)
                       (%i2p-fail "Invalid session id"))
                      ((member result '("CANT_REACH_PEER" "TIMEOUT") :test #'string=)
                       (setf proxy-error nil)))
                (%i2p-fail "\"~A\"" full)))))
      (i2p-error (e)
        (when sock (ignore-errors (usocket:socket-close sock)))
        (bl.log:log-cat "i2p" "Error connecting to ~A:~D: ~A" host port e)
        (%i2p-check-control-sock session)
        (values nil proxy-error)))))

(defun i2p-session-listen (session)
  "Core Session::Listen (i2p.cpp:136-150): make sure the session exists and
open a STREAM ACCEPT connection. Returns the listening socket, or NIL after
logging why."
  (handler-case
      (bt:with-recursive-lock-held ((i2p-session-lock session))
        (%i2p-create-if-not-created session)
        (let ((sock (%i2p-hello session)))
          (handler-bind ((error (lambda (e) (declare (ignore e)) (ignore-errors (usocket:socket-close sock)))))
            (multiple-value-bind (keys full shown)
                (%i2p-request sock (format nil "STREAM ACCEPT ID=~A SILENT=false"
                                           (i2p-session-session-id session))
                              :check-ok nil)
              (let ((result (%i2p-reply-get keys "RESULT" shown full)))
                (cond ((string= result "OK") sock)
                      (t (when (string= result "INVALID_ID") (i2p-session-disconnect session))
                         (%i2p-fail "\"~A\"" full))))))))
    (i2p-error (e)
      (bl.log:log-error "Couldn't listen: ~A" e)
      (%i2p-check-control-sock session)
      nil)))

(defun i2p-session-accept (session sock stop-p)
  "Core Session::Accept (i2p.cpp:152-220): wait on the STREAM ACCEPT socket
SOCK for the router to name a connecting peer, whose .b32.i2p address (port
0) is returned; NIL, with the reason logged, on failure or once STOP-P says
so. A reply that is not a destination but an I2P_ERROR closes the session."
  (let ((errmsg nil) (disconnect nil))
    (loop
      (when (funcall stop-p)
        (bl.log:log-cat "i2p" "Accept was interrupted")
        (return-from i2p-session-accept nil))
      (when (socket-input-ready-p sock :timeout +i2p-max-wait-for-io-seconds+)
        (let ((line (handler-case (%i2p-recv-line sock +i2p-max-wait-for-io-seconds+)
                      (i2p-error (e) (setf errmsg (princ-to-string e)) nil))))
          (unless line (return))
          (handler-case
              (return-from i2p-session-accept
                (i2p-destination-address (%i2p-decode-base64 line)))
            (i2p-error (e)
              (if (search "RESULT=I2P_ERROR" line)
                  (setf errmsg (format nil "unexpected reply that hints the session is unusable: ~A" line)
                        disconnect t)
                  (setf errmsg (princ-to-string e)))
              (return))))))
    (bl.log:log-cat "i2p" "Error accepting~:[~; (will close the session)~]: ~A" disconnect errmsg)
    (if disconnect
        (i2p-session-disconnect session)
        (%i2p-check-control-sock session))
    nil))

;;; --- The node's sessions (Core CConnman::m_i2p_sam_session,
;;; m_unused_i2p_sessions) ---

(defvar *i2p-sam-session* nil
  "The PERSISTENT session, created at start when -i2psam is set and
-i2pacceptincoming is on (net.cpp:3473-3477); every outbound I2P dial uses it
then, and the accept thread listens through it.")

(defvar *unused-i2p-sessions* '()
  "Transient sessions a failed dial left behind, for the next dial to reuse
(net.cpp:463-479), at most +MAX-UNUSED-I2P-SESSIONS+.")
(defvar *unused-i2p-sessions-lock* (bt:make-lock "unused-i2p-sessions"))

(defun i2p-dial (host port)
  "ConnectNode's I2P branch (net.cpp:453-484): dial HOST:PORT through the
persistent session, or else through a transient one (reused from a failed
dial when there is one). Returns (VALUES socket proxy-error-p session) --
SESSION being the transient session the connection now owns, which lives
exactly as long as the connection."
  (let ((persistent *i2p-sam-session*))
    (if persistent
        (multiple-value-bind (sock proxy-error) (i2p-session-connect persistent host port)
          (values sock proxy-error nil))
        (let ((session (or (bt:with-lock-held (*unused-i2p-sessions-lock*)
                             (pop *unused-i2p-sessions*))
                           (make-i2p-session *i2p-sam-proxy*))))
          (multiple-value-bind (sock proxy-error) (i2p-session-connect session host port)
            (unless sock
              (bt:with-lock-held (*unused-i2p-sessions-lock*)
                (if (< (length *unused-i2p-sessions*) +max-unused-i2p-sessions+)
                    (push session *unused-i2p-sessions*)
                    (i2p-session-disconnect session))))
            (values sock proxy-error (and sock session)))))))

(defun i2p-reset-sessions ()
  "Destroy every session (Core resets m_i2p_sam_session and the unused queue
when connman stops, net.cpp:569)."
  (when *i2p-sam-session*
    (i2p-session-disconnect *i2p-sam-session*)
    (setf *i2p-sam-session* nil))
  (bt:with-lock-held (*unused-i2p-sessions-lock*)
    (mapc #'i2p-session-disconnect *unused-i2p-sessions*)
    (setf *unused-i2p-sessions* '())))

(defun i2p-accepted-connection (sock peer-address)
  "The connection an accepted I2P stream SOCK becomes, from PEER-ADDRESS
(\"<name>.b32.i2p\"), port 0 (Core CreateNodeFromAcceptedSocket with
conn.peer, net.cpp:3198)."
  (set-socket-non-blocking sock)
  (make-connection :socket sock :host peer-address :port +i2p-sam31-port+
                   :connected t :last-activity (bl.ser:get-node-time)))
