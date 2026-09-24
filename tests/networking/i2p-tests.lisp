(in-package #:bitcoin-lisp.tests)

;;;; The I2P SAM 3.1 client (Core i2p.cpp) against a scripted SAM bridge.

(def-suite :i2p-tests
  :description "I2P SAM sessions, dials and accepts (Core i2p.cpp, net.cpp)"
  :in :bitcoin-lisp-tests)

(in-suite :i2p-tests)

(defparameter +fake-i2p-destination+
  (let ((d (make-array 391 :element-type '(unsigned-byte 8) :initial-element 7)))
    ;; A 4-byte certificate (bytes 385-386 big-endian), so the destination is
    ;; 391 bytes -- Core's MyDestination reads that length.
    (setf (aref d 385) 0 (aref d 386) 4)
    d)
  "A binary I2P destination the fake bridge hands out.")

(defun %i2p-b64 (bytes)
  (map 'string (lambda (c) (case c (#\+ #\-) (#\/ #\~) (t c))) (bl.ser:encode-base64 bytes)))

(defun %fake-sam-bridge (&key (accept-peer nil))
  "A SAM bridge on 127.0.0.1 that answers every request OK the way i2pd does.
Returns (VALUES port requests stop-fn): REQUESTS is a list cell collecting
every request line, newest first. With ACCEPT-PEER (binary destination), a
STREAM ACCEPT is answered OK and then with that destination's line."
  (let* ((srv (usocket:socket-listen "127.0.0.1" 0 :element-type '(unsigned-byte 8)
                                                   :reuse-address t))
         (port (usocket:get-local-port srv))
         (requests (list nil))
         (threads '()))
    (flet ((serve (client)
             (let ((s (usocket:socket-stream client)))
               (flet ((reply (line)
                        (write-sequence (map '(vector (unsigned-byte 8)) #'char-code line) s)
                        (write-byte 10 s) (force-output s)))
                 (loop
                   (let ((line (with-output-to-string (o)
                                 (loop for b = (read-byte s nil nil)
                                       do (cond ((null b) (return-from serve))
                                                ((= b 10) (return))
                                                (t (write-char (code-char b) o)))))))
                     (push line (car requests))
                     (cond
                       ((uiop:string-prefix-p "HELLO" line) (reply "HELLO REPLY RESULT=OK VERSION=3.1"))
                       ((uiop:string-prefix-p "DEST GENERATE" line)
                        (reply (format nil "DEST REPLY PUB=x PRIV=~A" (%i2p-b64 +fake-i2p-destination+))))
                       ((uiop:string-prefix-p "SESSION CREATE" line)
                        (reply (format nil "SESSION STATUS RESULT=OK DESTINATION=~A"
                                       (%i2p-b64 +fake-i2p-destination+))))
                       ((uiop:string-prefix-p "NAMING LOOKUP" line)
                        (reply (format nil "NAMING REPLY RESULT=OK NAME=x VALUE=~A"
                                       (%i2p-b64 +fake-i2p-destination+))))
                       ((uiop:string-prefix-p "STREAM CONNECT" line)
                        (reply "STREAM STATUS RESULT=OK")
                        (reply "hello-from-peer"))
                       ((uiop:string-prefix-p "STREAM ACCEPT" line)
                        (reply "STREAM STATUS RESULT=OK")
                        (when accept-peer (reply (%i2p-b64 accept-peer)))))))))))
      (push (bt:make-thread
             (lambda ()
               (ignore-errors
                (loop (let ((c (usocket:socket-accept srv :element-type '(unsigned-byte 8))))
                        (push (bt:make-thread (lambda () (ignore-errors (serve c))) :name "fake-sam-conn")
                              threads)))))
             :name "fake-sam")
            threads))
    (values port requests
            (lambda ()
              (ignore-errors (usocket:socket-close srv))
              (dolist (th threads) (when (bt:thread-alive-p th) (ignore-errors (bt:destroy-thread th))))))))

(defmacro %with-fake-sam ((port requests &rest keys) &body body)
  (let ((stop (gensym "STOP")))
    `(multiple-value-bind (,port ,requests ,stop) (%fake-sam-bridge ,@keys)
       (let ((bl.net:*i2p-sam-proxy* (format nil "127.0.0.1:~D" ,port)))
         (unwind-protect (progn ,@body)
           (bl.net:i2p-reset-sessions)
           (funcall ,stop))))))

(defparameter +i2p-peer+ "zsxwyo6qcn3chqzwxnseusqgsnuw3maqnztkiypyfxtya4snkoka.b32.i2p")

(test i2p-dial-refuses-an-arbitrary-port-and-says-why-it-cannot-connect
  "Core Session::Connect (i2p.cpp:222-281): SAM 3.1 has no ports, so a dial to
port != 0 is refused before the bridge is touched and blames the address, not
the proxy; a bridge that cannot be reached is `Cannot connect to <sam>' and
IS a proxy error. p2p_i2p_ports.py:26-31 waits for both lines. Ours refused
every I2P dial."
  (let ((bl.net:*i2p-sam-proxy* (format nil "127.0.0.1:~D" (closed-loopback-port))))
    (unwind-protect
         (let ((session (bl.net:make-i2p-session bl.net:*i2p-sam-proxy*)))
           (multiple-value-bind (result text)
               (log-text-of "i2p" (lambda () (multiple-value-list
                                              (bl.net:i2p-session-connect session +i2p-peer+ 8333))))
             (is (equal '(nil nil) result))
             (is (search (format nil "Error connecting to ~A:8333, connection refused due to arbitrary port 8333" +i2p-peer+)
                         text)))
           (multiple-value-bind (result text)
               (log-text-of "i2p" (lambda () (multiple-value-list
                                              (bl.net:i2p-session-connect session +i2p-peer+ 0))))
             (is (equal '(nil t) result) "an unreachable bridge is a proxy error")
             (is (search "Creating transient I2P SAM session" text))
             (is (search (format nil "Error connecting to ~A:0: Cannot connect to ~A"
                                 +i2p-peer+ bl.net:*i2p-sam-proxy*)
                         text))))
      (bl.net:i2p-reset-sessions))))

(test i2p-transient-session-dials-through-the-bridge
  "A transient session: HELLO, SESSION CREATE ... DESTINATION=TRANSIENT, our
address from the returned destination, then on a fresh socket HELLO, NAMING
LOOKUP and STREAM CONNECT, after which the socket carries the peer's bytes
(i2p.cpp:222-281, :408-458). MAKE-TCP-CONNECTION takes this route for an
.b32.i2p target whenever -i2psam is set."
  (%with-fake-sam (port requests)
    (let ((session (bl.net:make-i2p-session bl.net:*i2p-sam-proxy*)))
      (multiple-value-bind (sock proxy-error) (bl.net:i2p-session-connect session +i2p-peer+ 0)
        (is-true sock)
        (is-false proxy-error)
        (when sock
          (is (equal "hello-from-peer"
                     (map 'string #'code-char
                          (loop for b = (read-byte (usocket:socket-stream sock))
                                until (= b 10) collect b))))
          (usocket:socket-close sock)))
      (is (equal (format nil "~A:0" (bl.net:i2p-destination-address (subseq +fake-i2p-destination+ 0 391)))
                 (bl.net:i2p-session-my-addr session)))
      (let ((sent (reverse (car requests))))
        (is (search "DESTINATION=TRANSIENT" (find "SESSION CREATE" sent :test #'search)))
        (is (find (format nil "NAMING LOOKUP NAME=~A" +i2p-peer+) sent :test #'string=))
        (is (find "STREAM CONNECT ID=" sent :test #'search))))
    ;; Through the ordinary dial entry point.
    (multiple-value-bind (conn proxy-failed) (bl.net:make-tcp-connection +i2p-peer+ 0)
      (is-true conn "an I2P target dials through the bridge")
      (is-false proxy-failed)
      (when conn (bl.net:close-connection conn)))))

(test i2p-persistent-session-keeps-its-key-and-accepts
  "A persistent session reads <datadir>/i2p_private_key, or DEST GENERATEs one
and saves it (i2p.cpp:359-374, :430-446), so the second session asks the
bridge for no new key; Listen + Accept turn the destination line the bridge
sends into the peer's .b32.i2p address (i2p.cpp:136-220)."
  (with-temp-directory (dir "bl-i2p")
    (let ((keyfile (merge-pathnames "i2p_private_key" dir))
          (peer-dest (make-array 391 :element-type '(unsigned-byte 8) :initial-element 9)))
      (setf (aref peer-dest 385) 0 (aref peer-dest 386) 4)
      (%with-fake-sam (port requests :accept-peer peer-dest)
        (let ((session (bl.net:make-i2p-session bl.net:*i2p-sam-proxy* keyfile)))
          (let ((first (bl.net:i2p-session-listen session)))
            (when first (usocket:socket-close first)))
          (is-true (probe-file keyfile) "the generated key is saved")
          (is (equalp +fake-i2p-destination+ (alexandria:read-file-into-byte-vector keyfile)))
          (is (find "DEST GENERATE SIGNATURE_TYPE=7" (car requests) :test #'string=))
          (let ((sock (bl.net:i2p-session-listen session)))
            (is-true sock)
            (when sock
              (is (equal (bl.net:i2p-destination-address peer-dest)
                         (bl.net:i2p-session-accept session sock (lambda () nil))))
              (usocket:socket-close sock))))
        ;; A second session reads the key back instead of generating one.
        (setf (car requests) nil)
        (bl.net:i2p-reset-sessions)
        (let ((session (bl.net:make-i2p-session bl.net:*i2p-sam-proxy* keyfile)))
          (let ((sock (bl.net:i2p-session-listen session)))
            (when sock (usocket:socket-close sock)))
          (is (null (find "DEST GENERATE" (car requests) :test #'search)))
          (is (find "SESSION CREATE" (car requests) :test #'search)))))))
