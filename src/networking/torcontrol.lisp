(in-package #:bitcoin-lisp.networking)

;;; Tor control-port client: inbound onion service (Core torcontrol.cpp)
;;;
;;; A long-lived side connection to the local Tor daemon's control port
;;; (default 127.0.0.1:9051, -torcontrol) that authenticates (HASHEDPASSWORD /
;;; NULL / SAFECOOKIE, in Core's preference order), requests a v3 onion
;;; service with ADD_ONION forwarding the chain's default port to our local
;;; onion listener, persists the service key to onion_v3_private_key, and
;;; registers the .onion address as a local address for self-advertisement
;;; (AddLocal LOCAL_MANUAL). The connection is held open for the service's
;;; lifetime — Tor tears the ephemeral service down when the control
;;; connection closes, which is also the (DEL_ONION-free) shutdown story.
;;; Disconnects reconnect with exponential backoff (1s x1.5, cap 600s).
;;;
;;; Structural divergence from Core: Core drives the protocol through
;;; libevent bufferevents with per-command reply callbacks; its command chain
;;; is nonetheless strictly sequential (each callback issues the next
;;; command), so this client issues the same commands synchronously on its
;;; own thread — same wire traffic, same states, no event loop. Core also
;;; never uses SETEVENTS, so between ADD_ONION and disconnect the socket
;;; carries nothing but the (ignored) possibility of async 6xx lines.

;;;; Constants (torcontrol.cpp:50-73)

(defconstant +default-tor-control-port+ 9051
  "Default Tor control port (Core DEFAULT_TOR_CONTROL_PORT, torcontrol.h:23).")

(defconstant +default-tor-socks-port+ 9050
  "Default Tor SOCKS port, for GETINFO net/listeners/socks fallback (Core
DEFAULT_TOR_SOCKS_PORT, torcontrol.h:22).")

(defconstant +tor-cookie-size+ 32
  "Size of the control-auth cookie file (control-spec).")

(defconstant +tor-nonce-size+ 32
  "Size of the client/server nonces for SAFECOOKIE.")

(defconstant +tor-reply-ok+ 250)
(defconstant +tor-reply-unrecognized+ 510)

(alexandria:define-constant +tor-safe-serverkey+ "Tor safe cookie authentication server-to-controller hash"
  :test #'equalp :documentation "HMAC key string for the SAFECOOKIE ServerHash (torcontrol.cpp:60).")

(alexandria:define-constant +tor-safe-clientkey+ "Tor safe cookie authentication controller-to-server hash"
  :test #'equalp :documentation "HMAC key string for the SAFECOOKIE client response (torcontrol.cpp:62).")

(defconstant +tor-reconnect-timeout-start+ 1.0
  "Initial reconnect backoff, seconds (Core RECONNECT_TIMEOUT_START).")

(defconstant +tor-reconnect-timeout-exp+ 1.5
  "Reconnect backoff growth factor (Core RECONNECT_TIMEOUT_EXP).")

(defconstant +tor-reconnect-timeout-max+ 600.0
  "Reconnect backoff cap, seconds (Core RECONNECT_TIMEOUT_MAX).")

(defconstant +max-tor-line-length+ 100000
  "Belt-and-suspenders cap on one control-port line (Core MAX_LINE_LENGTH):
the spec sets no limit; a longer line means a broken/hostile server, so we
disconnect rather than buffer without bound.")

(alexandria:define-constant +onion-private-key-file+ "onion_v3_private_key"
  :test #'equalp :documentation "Datadir filename holding the onion service's private key, verbatim as Tor
returned it (\"ED25519-V3:<base64>\") — same name and content as Core
(TorController::GetPrivateKeyFile, torcontrol.cpp:665-668).")

;;;; Reply-line parsing (pure functions; torcontrol.cpp:88-131, 214-324)

(defun parse-tor-reply-line (line)
  "Parse one control-port reply LINE, '<3-digit-status><sep><data>' with sep
one of '-' (more lines follow), '+' (data line) or ' ' (final line). Returns
(VALUES code sep data), or NIL for a short (<4 chars) line — which the reader
skips, exactly as Core's readcb does. A non-numeric status parses as code 0
(Core ToIntegral .value_or(0))."
  (when (>= (length line) 4)
    (let ((code (if (every #'digit-char-p (subseq line 0 3))
                    (parse-integer line :end 3)
                    0)))
      (values code (char line 3) (subseq line 4)))))

(defun split-tor-reply-line (s)
  "Split a reply line body 'TYPE rest...' at the first space into
(VALUES type rest) — Core SplitTorReplyLine (torcontrol.cpp:214-225)."
  (let ((space (position #\Space s)))
    (if space
        (values (subseq s 0 space) (subseq s (1+ space)))
        (values s ""))))

(defun %unescape-tor-quoted-value (value)
  "Unescape the backslash escapes inside a QuotedString value per
control-spec 2.1.1 as Core interprets it (torcontrol.cpp:260-312): \\n \\t
\\r, octal escapes of up to three digits (a three-digit octal whose first
digit exceeds '3' is read as two digits), and backslash before anything else
yields that character. VALUE still contains the raw backslashes; the caller
guarantees it does not end in a dangling backslash."
  (let ((out (make-string-output-stream))
        (i 0)
        (n (length value)))
    (loop while (< i n)
          do (let ((ch (char value i)))
               (cond
                 ((char/= ch #\\)
                  (write-char ch out)
                  (incf i))
                 (t
                  (incf i)              ; skip the backslash
                  (let ((esc (char value i)))
                    (cond
                      ((char= esc #\n) (write-char #\Newline out) (incf i))
                      ((char= esc #\t) (write-char #\Tab out) (incf i))
                      ((char= esc #\r) (write-char #\Return out) (incf i))
                      ((char<= #\0 esc #\7)
                       ;; Up to three octal digits; Tor restricts the first
                       ;; digit of a THREE-digit octal to 0-3, so a leading
                       ;; 4-7 makes it a two-digit octal.
                       (let ((j 1))
                         (loop while (and (< j 3) (< (+ i j) n)
                                          (char<= #\0 (char value (+ i j)) #\7))
                               do (incf j))
                         (when (and (= j 3) (char> esc #\3))
                           (decf j))
                         (let ((val 0))
                           (dotimes (k j)
                             (setf val (+ (* val 8)
                                          (digit-char-p (char value (+ i k))))))
                           (write-char (code-char (logand val #xFF)) out))
                         (incf i j)))
                      (t (write-char esc out) (incf i))))))))
    (get-output-stream-string out)))

(defun parse-tor-reply-mapping (s)
  "Parse reply arguments 'KEY=VALUE KEY=\"quoted value\" ...' into an alist
of (key . value) strings, preserving order — Core ParseTorReplyMapping
(torcontrol.cpp:233-324). Values may be quoted (with the escapes of
%unescape-tor-quoted-value) or unquoted (anything up to a space; '=' is
fine inside). A key with no '=' means the rest of the line is OptArguments:
parsing stops there. Returns NIL on malformed input (unterminated quote,
line ending inside a key) — Core's empty-map error convention."
  (let ((out '())
        (ptr 0)
        (n (length s)))
    (loop while (< ptr n)
          do (let ((key-start ptr))
               (loop while (and (< ptr n)
                                (char/= (char s ptr) #\=)
                                (char/= (char s ptr) #\Space))
                     do (incf ptr))
               (when (= ptr n)          ; unexpected end of line
                 (return-from parse-tor-reply-mapping nil))
               (when (char= (char s ptr) #\Space)
                 ;; Remainder is an OptArguments — stop.
                 (return-from parse-tor-reply-mapping (nreverse out)))
               (let ((key (subseq s key-start ptr))
                     (value nil))
                 (incf ptr)             ; skip '='
                 (cond
                   ((and (< ptr n) (char= (char s ptr) #\"))
                    ;; Quoted string; repeated backslashes pair up.
                    (incf ptr)
                    (let ((value-start ptr)
                          (escape-next nil))
                      (loop while (and (< ptr n)
                                       (or escape-next
                                           (char/= (char s ptr) #\")))
                            do (setf escape-next
                                     (and (char= (char s ptr) #\\)
                                          (not escape-next)))
                               (incf ptr))
                      (when (= ptr n)   ; unterminated quote
                        (return-from parse-tor-reply-mapping nil))
                      (setf value (%unescape-tor-quoted-value
                                   (subseq s value-start ptr)))
                      (incf ptr)))      ; skip closing '"'
                   (t
                    (let ((value-start ptr))
                      (loop while (and (< ptr n) (char/= (char s ptr) #\Space))
                            do (incf ptr))
                      (setf value (subseq s value-start ptr)))))
                 (when (and (< ptr n) (char= (char s ptr) #\Space))
                   (incf ptr))
                 (push (cons key value) out))))
    (nreverse out)))

(defun tor-mapping-value (mapping key)
  "The value for KEY in a parse-tor-reply-mapping alist, or NIL."
  (cdr (assoc key mapping :test #'string=)))

;;;; SAFECOOKIE response (torcontrol.cpp:488-513)

(defun compute-safecookie-response (key-string cookie client-nonce server-nonce)
  "HMAC-SHA256 with KEY-STRING (one of the two Tor SAFECOOKIE key strings)
over COOKIE || CLIENT-NONCE || SERVER-NONCE (Core ComputeResponse)."
  (bl.crypto:hmac-sha256 (%string-bytes key-string)
                                   cookie client-nonce server-nonce))

;;;; Controller state

(defstruct tor-controller
  "State of the Tor control connection + the onion service it maintains
(Core TorController)."
  (control-host "127.0.0.1" :type string)
  (control-port +default-tor-control-port+ :type (unsigned-byte 16))
  ;; Where Tor forwards inbound onion connections: our local onion listener.
  (target-host "127.0.0.1" :type string)
  (target-port 0 :type (unsigned-byte 16))
  ;; The onion service's public port — always the chain default port, to
  ;; avoid decloaking nodes using nonstandard ports (torcontrol.cpp:480).
  (virtual-port 0 :type (unsigned-byte 16))
  ;; Path of the persisted service key (datadir/onion_v3_private_key).
  (private-key-file nil :type (or null pathname string))
  ;; The key string exactly as Tor speaks it ("ED25519-V3:<base64>"), or NIL
  ;; before the first ADD_ONION ever succeeds.
  (private-key nil :type (or null string))
  ;; -torpassword, for HASHEDPASSWORD auth.
  (password nil :type (or null string))
  ;; The registered service's 32-byte ed25519 pubkey (what add-local /
  ;; remove-local key on), or NIL while no service exists. The 56-char
  ;; service id is DERIVED from it (tor-controller-service-id below), so
  ;; there is no two-slot sync invariant.
  (service-pubkey nil :type (or null (simple-array (unsigned-byte 8) (*))))
  (socket nil)
  (reconnect-timeout +tor-reconnect-timeout-start+ :type single-float)
  (running t :type boolean)
  (thread nil :type (or null bt:thread)))

(defun tor-controller-service-id (ctl)
  "The 56-char onion service id while a service is registered, else NIL —
derived from the pubkey (the id is its base32 form, onion codec minus the
\".onion\" suffix)."
  (let ((pubkey (tor-controller-service-pubkey ctl)))
    (when pubkey
      (let ((onion (onion-address-string pubkey)))
        (subseq onion 0 (- (length onion) (length ".onion")))))))

(defun %tor-stopped-p (ctl)
  (or (not (tor-controller-running ctl)) (ibd-stop-requested-p)))

;;;; Line I/O
;;;
;;; The control connection legitimately idles for hours (Core attaches no
;;; timeout to reply callbacks either), so reads block indefinitely but stay
;;; interruptible: wait-for-input in short windows, polling stop flags.

(define-condition tor-control-error (net-error)
  ((message :initarg :message :reader tor-control-error-message))
  (:report (lambda (c stream)
             (format stream "tor control: ~A" (tor-control-error-message c))))
  (:documentation "Signaled on a broken/overlong control connection; the
session unwinds to the reconnect loop."))

(defun %tor-read-line (ctl)
  "Read one CRLF-terminated line from the control socket. Returns the line
without its CRLF, or NIL on EOF/shutdown. Signals tor-control-error past
+max-tor-line-length+ (Core disconnects there too). A bare LF also
terminates (tolerant superset; Tor always sends CRLF)."
  (let* ((socket (tor-controller-socket ctl))
         (stream (and socket (usocket:socket-stream socket)))
         (out (make-array 128 :element-type 'character
                              :adjustable t :fill-pointer 0)))
    (unless stream (return-from %tor-read-line nil))
    (loop
      (when (%tor-stopped-p ctl)
        (return-from %tor-read-line nil))
      (let ((byte (handler-case
                      ;; listen: only block in read-byte when data is already
                      ;; buffered or the 1s wait said ready — keeps shutdown
                      ;; latency ~1s.
                      (if (or (listen stream)
                              (socket-input-ready-p socket :timeout 1))
                          (read-byte stream nil :eof)
                          :again)
                    (error () :eof))))
        (case byte
          (:again)                      ; spurious wakeup / timeout: re-poll
          (:eof (return-from %tor-read-line nil))
          (t
           (let ((ch (code-char byte)))
             (cond
               ((char= ch #\Newline)
                ;; Strip a preceding CR (CRLF framing).
                (let ((len (fill-pointer out)))
                  (when (and (plusp len) (char= (aref out (1- len)) #\Return))
                    (decf (fill-pointer out))))
                (return-from %tor-read-line (coerce out 'string)))
               (t
                (when (>= (fill-pointer out) +max-tor-line-length+)
                  (error 'tor-control-error
                         :message "disconnecting because MAX_LINE_LENGTH exceeded"))
                (vector-push-extend ch out))))))))))

(defun %tor-write-line (ctl line)
  "Send LINE + CRLF on the control socket (Core Command's evbuffer_add)."
  (let* ((socket (tor-controller-socket ctl))
         (stream (and socket (usocket:socket-stream socket))))
    (unless stream
      (error 'tor-control-error :message "not connected"))
    (handler-case
        (progn
          (write-sequence (%string-bytes line) stream)
          (write-sequence #(13 10) stream)
          (force-output stream))
      (error (e)
        (error 'tor-control-error :message (format nil "send failed: ~A" e))))))

(defun tor-read-reply (ctl)
  "Read one synchronous reply: lines accumulate until the ' '-separated final
line; a complete >=600-coded (async event) message is discarded and reading
continues (Core readcb, torcontrol.cpp:96-123 — sync and async messages are
never interleaved). Returns (VALUES code lines) with LINES the per-line data
parts, or NIL on EOF/shutdown."
  (let ((code 0)
        (lines '()))
    (loop
      (let ((raw (%tor-read-line ctl)))
        (unless raw (return-from tor-read-reply nil))
        (multiple-value-bind (line-code sep data) (parse-tor-reply-line raw)
          (when line-code               ; short lines are skipped
            (setf code line-code)
            (push data lines)
            (when (char= sep #\Space)   ; final line of this message
              (if (>= code 600)
                  (progn                ; async notification: drop, keep reading
                    (bl.log:log-cat "tor" "Ignoring async event ~D" code)
                    (setf code 0 lines '()))
                  (return-from tor-read-reply
                    (values code (nreverse lines)))))))))))

(defun tor-command (ctl cmd &key sensitive)
  "Send CMD and wait for its reply — (VALUES code lines), or NIL on a dead
connection. SENSITIVE elides the command from the debug log (passwords)."
  (bl.log:log-cat "tor" "-> ~A" (if sensitive "AUTHENTICATE <elided>" cmd))
  (%tor-write-line ctl cmd)
  (tor-read-reply ctl))

;;;; Private key persistence

(defun read-onion-private-key (path)
  "The cached onion service key at PATH as a string, or NIL. Trailing
newline/CR are trimmed (the file we write has none, like Core's; a
hand-edited one shouldn't corrupt the ADD_ONION line)."
  (when (and path (probe-file path))
    (let ((raw (alexandria:read-file-into-string path)))
      (string-right-trim '(#\Newline #\Return) raw))))

(defun write-onion-private-key (path key)
  "Persist the service KEY string verbatim to PATH (Core WriteBinaryFile of
the PrivateKey reply value) and restrict it to owner read/write. Core leaves
the mode to the umask/datadir; 0600 is strictly tighter and matches how Tor
itself guards key material. Returns T on success."
  (handler-case
      (progn
        (with-open-file (out path :direction :output
                                  :if-exists :supersede
                                  :if-does-not-exist :create)
          (write-string key out))
        #+sbcl (sb-posix:chmod (namestring (truename path)) #o600)
        t)
    (error (e)
      (bl.log:log-warn "tor: Error writing service private key to ~A: ~A"
                             path e)
      nil)))

;;;; Auth (torcontrol.cpp:464-624)

(defun %tor-authenticate-safecookie (ctl cookiefile)
  "SAFECOOKIE authentication (torcontrol.cpp:599-615 + authchallenge_cb):
read the 32-byte cookie, AUTHCHALLENGE with a fresh client nonce, verify the
server's HMAC proof of cookie knowledge, then AUTHENTICATE with ours.
Returns the final reply code, or NIL on any protocol/verification failure."
  (let ((cookie (handler-case
                    (alexandria:read-file-into-byte-vector cookiefile)
                  (error ()
                    (bl.log:log-warn
                     "tor: Authentication cookie ~A could not be opened (check permissions)"
                     cookiefile)
                    (return-from %tor-authenticate-safecookie nil)))))
    (unless (= (length cookie) +tor-cookie-size+)
      (bl.log:log-warn
       "tor: Authentication cookie ~A is not exactly ~D bytes, as is required by the spec"
       cookiefile +tor-cookie-size+)
      (return-from %tor-authenticate-safecookie nil))
    (let ((client-nonce (ironclad:random-data +tor-nonce-size+)))
      (multiple-value-bind (code lines)
          (tor-command ctl (format nil "AUTHCHALLENGE SAFECOOKIE ~A"
                                   (bl.crypto:bytes-to-hex client-nonce)))
        (unless (eql code +tor-reply-ok+)
          (bl.log:log-warn "tor: SAFECOOKIE authentication challenge failed")
          (return-from %tor-authenticate-safecookie nil))
        (multiple-value-bind (type args) (split-tor-reply-line (first lines))
          (unless (string= type "AUTHCHALLENGE")
            (bl.log:log-warn "tor: Invalid reply to AUTHCHALLENGE")
            (return-from %tor-authenticate-safecookie nil))
          (let ((mapping (parse-tor-reply-mapping args)))
            (unless mapping
              (bl.log:log-warn "tor: Error parsing AUTHCHALLENGE parameters: ~A" args)
              (return-from %tor-authenticate-safecookie nil))
            (let ((server-hash (bl.crypto:hex-to-bytes
                                (or (tor-mapping-value mapping "SERVERHASH") "")))
                  (server-nonce (bl.crypto:hex-to-bytes
                                 (or (tor-mapping-value mapping "SERVERNONCE") ""))))
              (unless (= (length server-nonce) +tor-nonce-size+)
                (bl.log:log-warn
                 "tor: ServerNonce is not 32 bytes, as required by spec")
                (return-from %tor-authenticate-safecookie nil))
              ;; The server proves knowledge of the cookie first.
              (unless (equalp (compute-safecookie-response
                               +tor-safe-serverkey+ cookie client-nonce server-nonce)
                              server-hash)
                (bl.log:log-warn
                 "tor: ServerHash ~A does not match expected value"
                 (bl.crypto:bytes-to-hex server-hash))
                (return-from %tor-authenticate-safecookie nil))
              (tor-command
               ctl (format nil "AUTHENTICATE ~A"
                           (bl.crypto:bytes-to-hex
                            (compute-safecookie-response
                             +tor-safe-clientkey+ cookie
                             client-nonce server-nonce)))))))))))

(defun %tor-authenticate (ctl)
  "PROTOCOLINFO + the auth method dance (Core protocolinfo_cb):
HASHEDPASSWORD when -torpassword is given (and offered), else NULL, else
SAFECOOKIE. Returns T on a 250 to AUTHENTICATE."
  (multiple-value-bind (code lines) (tor-command ctl "PROTOCOLINFO 1")
    (unless (eql code +tor-reply-ok+)
      (bl.log:log-warn "tor: Requesting protocol info failed")
      (return-from %tor-authenticate nil))
    (let ((methods '())
          (cookiefile nil))
      (dolist (line lines)
        (multiple-value-bind (type args) (split-tor-reply-line line)
          (cond
            ((string= type "AUTH")
             (let ((mapping (parse-tor-reply-mapping args)))
               (let ((m (tor-mapping-value mapping "METHODS")))
                 (when m (setf methods (uiop:split-string m :separator ","))))
               (let ((f (tor-mapping-value mapping "COOKIEFILE")))
                 (when f (setf cookiefile f)))))
            ((string= type "VERSION")
             (let ((v (tor-mapping-value (parse-tor-reply-mapping args) "Tor")))
               (when v
                 (bl.log:log-cat "tor" "Connected to Tor version ~A" v)))))))
      (let* ((password (tor-controller-password ctl))
             (auth-code
               (cond
                 ((and password (plusp (length password)))
                  (cond
                    ((member "HASHEDPASSWORD" methods :test #'string=)
                     (bl.log:log-cat "tor" "Using HASHEDPASSWORD authentication")
                     ;; Escape double quotes inside the QuotedString.
                     (let ((escaped (with-output-to-string (s)
                                      (loop for ch across password
                                            do (when (char= ch #\") (write-char #\\ s))
                                               (write-char ch s)))))
                       (tor-command
                        ctl (format nil "AUTHENTICATE \"~A\"" escaped)
                        :sensitive t)))
                    (t
                     (bl.log:log-warn
                      "tor: Password provided with -torpassword, but HASHEDPASSWORD authentication is not available")
                     nil)))
                 ((member "NULL" methods :test #'string=)
                  (bl.log:log-cat "tor" "Using NULL authentication")
                  (tor-command ctl "AUTHENTICATE"))
                 ((member "SAFECOOKIE" methods :test #'string=)
                  (bl.log:log-cat
                   "tor" "Using SAFECOOKIE authentication, cookie file ~A" cookiefile)
                  (%tor-authenticate-safecookie ctl cookiefile))
                 ((member "HASHEDPASSWORD" methods :test #'string=)
                  (bl.log:log-warn
                   "tor: The only supported authentication mechanism left is password, but no password provided with -torpassword")
                  nil)
                 (t
                  (bl.log:log-warn "tor: No supported authentication method")
                  nil))))
        (cond
          ((eql auth-code +tor-reply-ok+)
           (bl.log:log-cat "tor" "Authentication successful")
           t)
          (auth-code
           (bl.log:log-warn "tor: Authentication failed")
           nil))))))

;;;; Onion proxy auto-configuration (Core get_socks_cb, torcontrol.cpp:358-427)

(defun %tor-configure-onion-proxy (ctl)
  "When -onion was never given, learn Tor's own SOCKS listener via GETINFO
net/listeners/socks and install it as the onion proxy (with stream isolation,
as Core hardcodes there), then admit :torv3 to the reachable set unless
-onlynet excludes it. This is what makes a bare `-torcontrol` node able to
DIAL onion peers, not just serve them."
  (when *onion-proxy-explicit*
    (return-from %tor-configure-onion-proxy nil))
  (multiple-value-bind (code lines) (tor-command ctl "GETINFO net/listeners/socks")
    (unless code (return-from %tor-configure-onion-proxy nil))
    (let ((socks-location nil))
      (cond
        ((eql code +tor-reply-ok+)
         (dolist (line lines)
           (let ((prefix "net/listeners/socks="))
             (when (and (>= (length line) (length prefix))
                        (string= prefix line :end2 (length prefix)))
               (dolist (portstr (uiop:split-string (subseq line (length prefix))
                                                   :separator " "))
                 ;; Entries may be quoted ("127.0.0.1:9050").
                 (when (and (>= (length portstr) 2)
                            (member (char portstr 0) '(#\" #\'))
                            (char= (char portstr (1- (length portstr)))
                                   (char portstr 0)))
                   (setf portstr (subseq portstr 1 (1- (length portstr)))))
                 (when (plusp (length portstr))
                   (setf socks-location portstr)
                   (when (uiop:string-prefix-p "127.0.0.1:" portstr)
                     (return)))))))    ; prefer localhost — ignore the rest
         (if socks-location
             (bl.log:log-cat "tor" "Get SOCKS port command yielded ~A"
                                   socks-location)
             (bl.log:log-warn "tor: Get SOCKS port command returned nothing")))
        ((eql code +tor-reply-unrecognized+)
         (bl.log:log-warn
          "tor: Get SOCKS port command failed with unrecognized command (You probably should upgrade Tor)"))
        (t
         (bl.log:log-warn "tor: Get SOCKS port command failed; error code ~D"
                                code)))
      (multiple-value-bind (host port)
          ;; Fallback to the old behaviour (127.0.0.1:9050) when Tor
          ;; reported nothing usable.
          (split-host-port (or socks-location "127.0.0.1")
                           +default-tor-socks-port+)
        (bl.log:log-cat "tor" "Configuring onion proxy for ~A:~D" host port)
        ;; Stream isolation unconditionally, as Core does on this path.
        (setf *onion-proxy* (make-proxy :host host :port port
                                        :randomize-credentials t))
        (admit-reachable-network :torv3)))))

;;;; ADD_ONION (torcontrol.cpp:429-462, 476-481)

(defun tor-add-onion-command (ctl)
  "The ADD_ONION command line: the cached private key (or NEW:ED25519-V3 on
first run — key type explicit, Core issue bitcoin/bitcoin#9214) with the virtual port fixed
at the chain default, forwarding to our local onion listener."
  (format nil "ADD_ONION ~A Port=~D,~A:~D"
          (or (tor-controller-private-key ctl) "NEW:ED25519-V3")
          (tor-controller-virtual-port ctl)
          (tor-controller-target-host ctl)
          (tor-controller-target-port ctl)))

(defun %tor-add-onion (ctl)
  "Request the onion service and register it (Core add_onion_cb): parse
ServiceID/PrivateKey from the reply, persist the key, AddLocal the .onion
address at LOCAL_MANUAL. Restoring from a cached key gets no PrivateKey line
back — the cached one stays. 512/551 (bad arguments / key failure) land in
the generic error arm, as in Core: logged, no retry, connection stays up."
  (multiple-value-bind (code lines) (tor-command ctl (tor-add-onion-command ctl))
    (cond
      ((eql code +tor-reply-ok+)
       (let ((sid nil))
         (dolist (line lines)
           (let ((mapping (parse-tor-reply-mapping line)))
             (let ((s (tor-mapping-value mapping "ServiceID")))
               (when s (setf sid s)))
             (let ((key (tor-mapping-value mapping "PrivateKey")))
               (when key (setf (tor-controller-private-key ctl) key)))))
         (unless sid
           (bl.log:log-warn "tor: Error parsing ADD_ONION parameters:~{ ~A~}"
                                  lines)
           (return-from %tor-add-onion nil))
         (let ((pubkey (parse-onion-address (concatenate 'string sid ".onion"))))
           (unless pubkey
             (bl.log:log-warn "tor: Invalid ServiceID in ADD_ONION reply: ~A" sid)
             (return-from %tor-add-onion nil))
           (setf (tor-controller-service-pubkey ctl) pubkey)
           (bl.log:log-info
            "tor: Got service ID ~A, advertising service ~A.onion:~D"
            sid sid (tor-controller-virtual-port ctl))
           (when (and (tor-controller-private-key ctl)
                      (tor-controller-private-key-file ctl)
                      (write-onion-private-key
                       (tor-controller-private-key-file ctl)
                       (tor-controller-private-key ctl)))
             (bl.log:log-cat "tor" "Cached service private key to ~A"
                                   (tor-controller-private-key-file ctl)))
           (add-local :torv3 pubkey (tor-controller-virtual-port ctl)
                      +local-manual+)
           t)))
      ((eql code +tor-reply-unrecognized+)
       (bl.log:log-warn
        "tor: Add onion failed with unrecognized command (You probably need to upgrade Tor)")
       nil)
      (code
       (bl.log:log-warn "tor: Add onion failed; error code ~D" code)
       nil))))

;;;; Session + reconnect loop (Core connected_cb / disconnected_cb / Reconnect)

(defun %tor-forget-service (ctl)
  "Stop advertising the service (Core disconnected_cb's RemoveLocal): the
control connection is gone, so Tor has torn the ephemeral service down."
  (let ((pubkey (tor-controller-service-pubkey ctl)))
    (when pubkey
      (remove-local :torv3 pubkey)
      (setf (tor-controller-service-pubkey ctl) nil))))

(defun %tor-session (ctl)
  "One connected session: authenticate, auto-configure the onion proxy,
ADD_ONION, then hold the connection open (nothing further is expected —
Core never subscribes to events) until EOF or shutdown."
  (when (%tor-authenticate ctl)
    (%tor-configure-onion-proxy ctl)
    (%tor-add-onion ctl))
  ;; Hold open for the service's lifetime; drain (and ignore) anything that
  ;; arrives. NIL = EOF or shutdown. Core behaves the same when auth fails:
  ;; the connection idles until one side closes it.
  (loop while (%tor-read-line ctl)))

(defun %tor-connect (ctl)
  "Open the control-port TCP connection. Returns T on success."
  (handler-case
      (progn
        (setf (tor-controller-socket ctl)
              (usocket:socket-connect (tor-controller-control-host ctl)
                                      (tor-controller-control-port ctl)
                                      :element-type '(unsigned-byte 8)
                                      :timeout 10))
        (bl.log:log-cat "tor" "Successfully connected to Tor control port ~A:~D"
                              (tor-controller-control-host ctl)
                              (tor-controller-control-port ctl))
        t)
    (error ()
      (setf (tor-controller-socket ctl) nil)
      nil)))

(defun %tor-disconnect (ctl)
  (let ((socket (tor-controller-socket ctl)))
    (setf (tor-controller-socket ctl) nil)
    (when socket
      (ignore-errors (usocket:socket-close socket)))))

(defun %tor-sleep-backoff (ctl)
  "Sleep the current reconnect backoff (interruptible), then grow it:
1s x1.5 capped at 600s (Core disconnected_cb, torcontrol.cpp:643-651)."
  (let ((timeout (tor-controller-reconnect-timeout ctl)))
    (bl.log:log-cat
     "tor" "Not connected to Tor control port ~A:~D, retrying in ~,2F s"
     (tor-controller-control-host ctl) (tor-controller-control-port ctl) timeout)
    (let ((deadline (+ (get-internal-real-time)
                       (round (* timeout internal-time-units-per-second)))))
      (loop while (and (< (get-internal-real-time) deadline)
                       (not (%tor-stopped-p ctl)))
            do (sleep 0.1)))
    (setf (tor-controller-reconnect-timeout ctl)
          (min (* timeout +tor-reconnect-timeout-exp+)
               +tor-reconnect-timeout-max+))))

(defun %torcontrol-loop (ctl)
  "The torcontrol thread body: connect / run session / clean up / back off,
until stopped."
  (loop until (%tor-stopped-p ctl)
        do (if (%tor-connect ctl)
               (progn
                 ;; Backoff resets on TCP connect (Core connected_cb).
                 (setf (tor-controller-reconnect-timeout ctl)
                       +tor-reconnect-timeout-start+)
                 (unwind-protect
                      (handler-case (%tor-session ctl)
                        (tor-control-error (e)
                          (bl.log:log-warn "tor: ~A"
                                                 (tor-control-error-message e)))
                        (error (e)
                          (bl.log:log-warn "tor: control session error: ~A" e)))
                   (%tor-disconnect ctl)
                   (%tor-forget-service ctl)))
               (%tor-disconnect ctl))
           (unless (%tor-stopped-p ctl)
             (%tor-sleep-backoff ctl))))

;;;; Start / stop (Core StartTorControl / InterruptTorControl / StopTorControl)

(defun parse-torcontrol-spec (spec)
  "Parse a -torcontrol \"host[:port]\" SPEC into (VALUES host port), port
defaulting to 9051 (Core: Lookup(..., DEFAULT_TOR_CONTROL_PORT, ...)).
NIL/empty means the default 127.0.0.1:9051; splitting rules are
split-host-port's (netaddress.lisp)."
  (let ((v (string-trim '(#\Space #\Tab) (or spec ""))))
    (if (zerop (length v))
        (values "127.0.0.1" +default-tor-control-port+)
        (split-host-port v +default-tor-control-port+))))

(defun start-tor-control (&key control-spec password data-directory
                               virtual-port target-port
                               (target-host "127.0.0.1"))
  "Launch the torcontrol client thread (Core StartTorControl): it will keep
a control connection up (with backoff), maintain the onion service mapping
VIRTUAL-PORT (the chain default port) to TARGET-HOST:TARGET-PORT (our onion
listener), and persist the service key under DATA-DIRECTORY. Returns the
tor-controller."
  (multiple-value-bind (host port) (parse-torcontrol-spec control-spec)
    (let* ((key-file (merge-pathnames +onion-private-key-file+ data-directory))
           (ctl (make-tor-controller
                 :control-host host
                 :control-port port
                 :target-host target-host
                 :target-port target-port
                 :virtual-port virtual-port
                 :password password
                 :private-key-file key-file
                 :private-key (read-onion-private-key key-file))))
      (when (tor-controller-private-key ctl)
        (bl.log:log-cat "tor" "Reading cached private key from ~A" key-file))
      (setf (tor-controller-thread ctl)
            (bt:make-thread (lambda ()
                              (handler-case (%torcontrol-loop ctl)
                                (error (e)
                                  (bl.log:log-error
                                   "tor: control thread died: ~A" e))))
                            :name "torcontrol"))
      ctl)))

(defun stop-tor-control (ctl)
  "Stop the torcontrol thread and unregister the service. Closing the control
connection is also what destroys the ephemeral onion service inside Tor — no
DEL_ONION is sent, exactly like Core's shutdown."
  (when ctl
    (setf (tor-controller-running ctl) nil)
    (%tor-disconnect ctl)               ; unblocks any read
    (join-thread-or-destroy (tor-controller-thread ctl))
    (setf (tor-controller-thread ctl) nil)
    (%tor-forget-service ctl)
    t))
