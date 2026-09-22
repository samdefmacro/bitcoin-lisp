(in-package #:bitcoin-lisp.cli)

;;;; The HTTP exchange of one call (Core bitcoin-cli.cpp CallRPC's libevent half)
;;;
;;; One POST per connection with `Connection: close', as Core sends it, and
;;; the reply read to its Content-Length (or its chunks, or EOF). What Core
;;; learns from libevent is a status code and a body -- or, when there is no
;;; reply at all, an error code whose text it prints (http_errorstring). That
;;; is exactly this layer's interface, so the rest of the client is tested
;;; against a stub transport and never needs a server (*CLI-TRANSPORT*).

(define-condition cli-transport-failure (error)
  ((code :initarg :code :reader cli-transport-failure-code))
  (:report (lambda (c s) (format s "HTTP request failed (~A)" (cli-transport-failure-code c))))
  (:documentation "No HTTP reply: the connection failed or timed out. CODE is
libevent's evhttp_request_error (0 timeout, 1 EOF, ...) or -1 when unknown."))

(defun http-error-string (code)
  "Core http_errorstring (bitcoin-cli.cpp:207-225)."
  (case code
    (0 "timeout reached")
    (1 "EOF reached")
    (2 "error while reading header, or invalid header")
    (3 "error encountered while reading or writing")
    (4 "request was canceled")
    (5 "response body is larger than allowed")
    (t "unknown")))

(defun uri-encode (string)
  "libevent evhttp_uriencode(.., space_as_plus=false), which Core applies to
the -rpcwallet name: every UTF-8 byte except the unreserved ALPHA / DIGIT /
- . _ ~ becomes %XX in upper-case hex."
  (with-output-to-string (out)
    (loop for byte across (sb-ext:string-to-octets string :external-format :utf-8)
          for c = (code-char byte)
          do (if (or (char<= #\A c #\Z) (char<= #\a c #\z) (char<= #\0 c #\9)
                     (member c '(#\- #\. #\_ #\~)))
                 (write-char c out)
                 (format out "%~2,'0X" byte)))))

(defun %read-line-crlf (stream)
  "One header line of STREAM as a Latin-1 string, CR LF stripped; NIL at EOF."
  (let ((bytes (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0)))
    (loop for b = (read-byte stream nil nil)
          do (cond ((null b) (return (and (plusp (length bytes))
                                           (map 'string #'code-char bytes))))
                   ((= b 10)
                    (when (and (plusp (length bytes)) (= (aref bytes (1- (length bytes))) 13))
                      (vector-pop bytes))
                    (return (map 'string #'code-char bytes)))
                   (t (vector-push-extend b bytes))))))

(defun %read-octets (stream n)
  (let* ((buf (make-array n :element-type '(unsigned-byte 8)))
         (got (read-sequence buf stream)))
    (if (= got n) buf (subseq buf 0 got))))

(defun %read-to-eof (stream)
  (let ((chunks nil) (buf (make-array 65536 :element-type '(unsigned-byte 8))))
    (loop for n = (read-sequence buf stream)
          while (plusp n) do (push (subseq buf 0 n) chunks)
          while (= n (length buf)))
    (apply #'concatenate '(vector (unsigned-byte 8)) (nreverse chunks))))

(defun %read-chunked (stream)
  (let ((chunks nil))
    (loop for line = (%read-line-crlf stream)
          for size = (and line (parse-integer line :radix 16 :junk-allowed t))
          while (and size (plusp size))
          do (push (%read-octets stream size) chunks)
             (%read-line-crlf stream))
    (apply #'concatenate '(vector (unsigned-byte 8)) (nreverse chunks))))

(defun read-http-response (stream)
  "Read one HTTP/1.x response from the octet STREAM: (VALUES status body),
BODY decoded as UTF-8. A reply with no status line is an EOF failure."
  (let* ((status-line (or (%read-line-crlf stream)
                          (error 'cli-transport-failure :code 1)))
         (status (let ((sp (position #\Space status-line)))
                   (or (and sp (parse-integer status-line :start (1+ sp) :junk-allowed t))
                       (error 'cli-transport-failure :code 2))))
         (headers (loop for line = (%read-line-crlf stream)
                        while (and line (plusp (length line)))
                        collect (let ((colon (position #\: line)))
                                  (cons (string-downcase (subseq line 0 (or colon 0)))
                                        (if colon (string-trim " " (subseq line (1+ colon))) "")))))
         (length (let ((v (cdr (assoc "content-length" headers :test #'string=))))
                   (and v (parse-integer v :junk-allowed t))))
         (chunked (search "chunked" (or (cdr (assoc "transfer-encoding" headers
                                                    :test #'string=))
                                        "")))
         (octets (cond (chunked (%read-chunked stream))
                       (length (%read-octets stream length))
                       (t (%read-to-eof stream)))))
    (values status (sb-ext:octets-to-string octets :external-format :utf-8))))

(defun %resolve (host)
  "The socket class and address to reach HOST: a numeric IPv6 or IPv4 literal
as it is, a name through the resolver (IPv4 first, as libevent tries it).
A literal is never handed to the resolver: glibc answers getaddrinfo(\"::1\")
with EAI_ADDRFAMILY under AI_ADDRCONFIG on a host whose only IPv6 address is
the loopback -- every Docker container -- which is exactly where
interface_bitcoin_cli.py tests -rpcconnect=[::1]."
  (let ((v6 (and (find #\: host)
                 (ignore-errors (sb-bsd-sockets:make-inet6-address host))))
        (v4 (ignore-errors (sb-bsd-sockets:make-inet-address host))))
    (cond (v6 (values 'sb-bsd-sockets:inet6-socket v6))
          ((and v4 (= 3 (count #\. host))) (values 'sb-bsd-sockets:inet-socket v4))
          (t (multiple-value-bind (host4 host6) (sb-bsd-sockets:get-host-by-name host)
               (cond (host4 (values 'sb-bsd-sockets:inet-socket
                                    (sb-bsd-sockets:host-ent-address host4)))
                     (host6 (values 'sb-bsd-sockets:inet6-socket
                                    (sb-bsd-sockets:host-ent-address host6)))
                     (t (error 'cli-transport-failure :code 1))))))))

(defun %connect (host port)
  "A connected TCP socket to HOST:PORT and its octet stream: (VALUES socket
stream). Any failure to connect is libevent's EOF error."
  (multiple-value-bind (class address)
      (handler-case (%resolve host)
        (sb-sys:deadline-timeout (e) (error e))
        (error () (error 'cli-transport-failure :code 1)))
    (let ((socket (make-instance class :type :stream :protocol :tcp)))
      (handler-case (sb-bsd-sockets:socket-connect socket address port)
        (sb-sys:deadline-timeout (e) (sb-bsd-sockets:socket-close socket) (error e))
        (error ()
          (ignore-errors (sb-bsd-sockets:socket-close socket))
          (error 'cli-transport-failure :code 1)))
      (values socket (sb-bsd-sockets:socket-make-stream socket :input t :output t
                                                               :element-type '(unsigned-byte 8)
                                                               :buffering :full)))))

(defun http-post (host port path headers body timeout)
  "POST BODY (a string) to http://HOST:PORT/PATH with HEADERS, an alist sent in
order after Host, and return (VALUES status body). TIMEOUT is in seconds, NIL
for none; it bounds the whole exchange, connect included, as libevent's
evhttp_connection_set_timeout does. Signals CLI-TRANSPORT-FAILURE when no
reply arrives."
  (flet ((exchange ()
           (multiple-value-bind (socket stream) (%connect host port)
             (unwind-protect
                  (let* ((payload (sb-ext:string-to-octets body :external-format :utf-8))
                         (head (with-output-to-string (out)
                                 (format out "POST ~A HTTP/1.1~C~C" path #\Return #\Newline)
                                 (format out "Host: ~A~C~C" host #\Return #\Newline)
                                 (loop for (k . v) in headers
                                       do (format out "~A: ~A~C~C" k v #\Return #\Newline))
                                 (format out "Content-Length: ~D~C~C~C~C"
                                         (length payload) #\Return #\Newline #\Return #\Newline))))
                    (handler-case
                        (progn
                          (write-sequence (sb-ext:string-to-octets head :external-format :latin-1)
                                          stream)
                          (write-sequence payload stream)
                          (finish-output stream))
                      (sb-sys:deadline-timeout (e) (error e))
                      (error () (error 'cli-transport-failure :code 3)))
                    (read-http-response stream))
               (ignore-errors (sb-bsd-sockets:socket-close socket))))))
    (handler-case
        (if (and timeout (plusp timeout))
            (sb-sys:with-deadline (:seconds timeout) (exchange))
            (exchange))
      (sb-sys:deadline-timeout () (error 'cli-transport-failure :code 0))
      (cli-transport-failure (e) (error e))
      (stream-error () (error 'cli-transport-failure :code 1)))))

(defvar *cli-transport* #'http-post
  "The function a call's HTTP exchange goes through: HTTP-POST, or a stub
with its lambda list in a test.")
