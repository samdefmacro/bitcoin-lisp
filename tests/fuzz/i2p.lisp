(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/i2p.cpp at the pin: an I2P SAM session -- Listen,
;;;; Accept, then Connect -- against a SAM bridge whose every reply is the
;;;; fuzzer's (Core mocks CreateSock to hand out FuzzedSocks). Ours is the SAM
;;;; 3.1 client of Round 8 (I2P-SESSION-LISTEN, -ACCEPT, -CONNECT) against a
;;;; loopback bridge that answers each request line with a reply the buffer
;;;; chooses: the well-formed answer to that request with fuzzed fields, a
;;;; RESULT that is not OK, raw bytes, a line cut short, or a hang-up.
;;;;
;;;; Core asserts only that the calls return. The client catches its own
;;;; failures (Core's std::runtime_error) and reports them, so any condition
;;;; escaping a call is a crash; and what it reports must be what the protocol
;;;; allows -- an accepted peer is a .b32.i2p name, a created session knows its
;;;; own .b32.i2p:0 address, and a stream the connect hands back comes with no
;;;; proxy error.

(def-suite :fuzz-i2p-tests :in :bitcoin-lisp-tests
  :description "Core fuzz i2p.cpp over our I2P SAM client")

(in-suite :fuzz-i2p-tests)

(defun %sam-b64 (bytes)
  "BYTES in I2P's Base64 (Core SwapBase64: '-' for '+', '~' for '/')."
  (map 'string (lambda (c) (case c (#\+ #\-) (#\/ #\~) (t c))) (bl.ser:encode-base64 bytes)))

(defun %fuzz-sam-key (fdp)
  "A private key or destination as the bridge would send it: 387 bytes plus a
certificate its bytes 385-386 size, the size and the tail fuzzed."
  (let* ((cert (pick-value-in-array fdp (list 4 0 7 (consume-integral fdp :u16))))
         (len (pick-value-in-array fdp (list (+ 387 cert) (+ 387 cert 32)
                                             (consume-integral-in-range fdp 0 600))))
         (key (make-array len :element-type '(unsigned-byte 8) :initial-element 7)))
    (when (> len 386)
      (setf (aref key 385) (ldb (byte 8 8) cert) (aref key 386) (ldb (byte 8 0) cert)))
    key))

(defun %fuzz-sam-reply (fdp request)
  "The bridge's answer to the REQUEST line: a list of lines to send (each
followed by a newline) and whether to hang up after them."
  (flet ((result () (if (plusp (consume-integral-in-range fdp 0 7))
                         "OK"
                         (pick-value-in-array fdp (list "CANT_REACH_PEER" "TIMEOUT" "INVALID_ID"
                                                        "I2P_ERROR" (consume-random-length-string fdp 8))))))
    (case (consume-integral-in-range fdp 0 15)
      (0 (values (list (consume-random-length-string fdp 80)) (consume-bool fdp)))
      (1 (values '() t))
      (t
       (let ((lines
               (cond
                 ((uiop:string-prefix-p "HELLO" request)
                  (list (format nil "HELLO REPLY RESULT=~A VERSION=3.1" (result))))
                 ((uiop:string-prefix-p "DEST GENERATE" request)
                  (list (format nil "DEST REPLY PUB=x PRIV=~A" (%sam-b64 (%fuzz-sam-key fdp)))))
                 ((uiop:string-prefix-p "SESSION CREATE" request)
                  (list (format nil "SESSION STATUS RESULT=~A DESTINATION=~A"
                                (result) (%sam-b64 (%fuzz-sam-key fdp)))))
                 ((uiop:string-prefix-p "NAMING LOOKUP" request)
                  (list (format nil "NAMING REPLY RESULT=~A NAME=x~:[~;~:* VALUE=~A~]"
                                (result) (and (consume-bool fdp) (%sam-b64 (%fuzz-sam-key fdp))))))
                 ((uiop:string-prefix-p "STREAM CONNECT" request)
                  (list (format nil "STREAM STATUS RESULT=~A" (result))))
                 ((uiop:string-prefix-p "STREAM ACCEPT" request)
                  (list* (format nil "STREAM STATUS RESULT=~A" (result))
                         (call-one-of fdp
                           (list (%sam-b64 (%fuzz-sam-key fdp)))
                           (list "STREAM STATUS RESULT=I2P_ERROR MESSAGE=\"x\"")
                           (list (consume-random-length-string fdp 80))
                           '())))
                 (t (list "UNKNOWN")))))
         ;; Now and then the last line loses its tail.
         (when (and lines (zerop (consume-integral-in-range fdp 0 15)))
           (let ((last (car (last lines))))
             (setf (car (last lines))
                   (subseq last 0 (consume-integral-in-range fdp 0 (length last))))))
         ;; An accept answered with its status line alone is followed by
         ;; a hang-up: a bridge that says nothing more would only cost the
         ;; accept loop its one-second wait (Core's MAX_WAIT_FOR_IO).
         (values lines (or (zerop (consume-integral-in-range fdp 0 7))
                           (and (uiop:string-prefix-p "STREAM ACCEPT" request)
                                (< (length lines) 2)))))))))

(defun %serve-sam-connection (fdp s)
  "Answer the request lines on the bridge connection S from FDP until the
client or the answer hangs up."
  (unwind-protect
       (let ((stream (usocket:socket-stream s)))
         (loop
           (let ((request (with-output-to-string (o)
                            (loop for b = (read-byte stream nil nil)
                                  do (cond ((null b) (return-from %serve-sam-connection))
                                           ((= b 10) (return))
                                           (t (write-char (code-char b) o)))))))
             (multiple-value-bind (lines hang-up) (%fuzz-sam-reply fdp request)
               (dolist (line lines)
                 (write-sequence (map '(vector (unsigned-byte 8))
                                      (lambda (c) (logand (char-code c) #xff))
                                      line)
                                 stream)
                 (write-byte 10 stream))
               (force-output stream)
               (when hang-up
                 (usocket:socket-shutdown s :output)
                 (loop while (read-byte stream nil nil))
                 (return))))))
    (ignore-errors (usocket:socket-close s))))

(defun call-with-fuzzed-sam-bridge (fdp fn)
  "Call FN with the \"host:port\" of a loopback SAM bridge that serves each
connection on a thread of its own (the client keeps its control connection
open while it opens the next one), answering every request line from FDP
(%FUZZ-SAM-REPLY). The client asks one question at a time, so the answers are
drawn in the order the requests are made. Every bridge thread is stopped and
joined before this returns."
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0 :element-type '(unsigned-byte 8)
                                                        :reuse-address t))
         (port (usocket:get-local-port listener))
         (stop nil)
         (servers '())
         (lock (bt:make-lock "fuzz-sam-bridge"))
         (acceptor
           (bt:make-thread
            (lambda ()
              (handler-case
                  (loop until stop
                        do (when (usocket:wait-for-input listener :timeout 0.02 :ready-only t)
                             (let ((s (usocket:socket-accept listener :element-type '(unsigned-byte 8))))
                               (bt:with-lock-held (lock)
                                 (push (bt:make-thread
                                        (lambda ()
                                          (handler-case (%serve-sam-connection fdp s)
                                            (error () nil)))
                                        :name "fuzz-sam-connection")
                                       servers)))))
                (error () nil)))
            :name "fuzz-sam-bridge")))
    (unwind-protect (funcall fn (format nil "127.0.0.1:~D" port))
      (setf stop t)
      (sb-thread:join-thread acceptor :default nil :timeout 10)
      (dolist (th (bt:with-lock-held (lock) servers))
        (unless (sb-thread:join-thread th :default nil :timeout 10)
          (ignore-errors (bt:destroy-thread th))))
      (ignore-errors (usocket:socket-close listener)))))

(define-fuzz-target i2p
    (buffer :core "i2p.cpp:30-66" :iterations 60 :max-len 800)
  "A SAM session -- transient or persistent -- listened, accepted on and
connected through against a bridge whose replies are the buffer's: every call
returns, and what it returns is what the protocol allows."
  (let ((fdp (make-fuzzed-data-provider buffer)))
    (with-temp-directory (dir "fuzz-i2p")
      (let ((persistent (consume-bool fdp))
            (target (format nil "~A.b32.i2p" (make-string 52 :initial-element #\a))))
        (call-with-fuzzed-sam-bridge
         fdp
         (lambda (host)
           (let ((session (bl.net:make-i2p-session
                           host (and persistent (merge-pathnames "i2p_private_key" dir))))
                 (checks 0))
             (unwind-protect
                  (flet ((check-addr ()
                           (let ((addr (bl.net:i2p-session-my-addr session)))
                             (when addr
                               (fuzz-assert (uiop:string-suffix-p addr ".b32.i2p:0")
                                            "the session's own address is ~S" addr)))))
                    (let ((sock (bl.net:i2p-session-listen session)))
                      (check-addr)
                      (when sock
                        (unwind-protect
                             (let ((peer (bl.net:i2p-session-accept
                                          session sock (lambda () (> (incf checks) 1)))))
                               (when peer
                                 (fuzz-assert (uiop:string-suffix-p (fuzz-sabotage peer) ".b32.i2p")
                                              "an accepted peer is ~S" peer)))
                          (ignore-errors (usocket:socket-close sock)))))
                    (multiple-value-bind (sock proxy-error)
                        (bl.net:i2p-session-connect session target 0)
                      (check-addr)
                      (when sock
                        (fuzz-assert (not (fuzz-sabotage proxy-error))
                                     "a connected stream came with a proxy error")
                        (ignore-errors (usocket:socket-close sock)))))
               (bl.net:i2p-session-disconnect session)))))))))
