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
  (bytes-received 0 :type integer))

(defun make-tcp-connection (host port &key (timeout 10))
  "Create a TCP connection to HOST:PORT.
Returns a connection structure or NIL on failure."
  (handler-case
      (let ((socket (usocket:socket-connect host port
                                            :element-type '(unsigned-byte 8)
                                            :timeout timeout)))
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
          (write-sequence bytes stream)
          (force-output stream)
          (incf (connection-bytes-sent conn) (length bytes))
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
          (when (usocket:wait-for-input socket :timeout timeout :ready-only t)
            (let* ((stream (connection-stream conn))
                   (buffer (make-array count :element-type '(unsigned-byte 8)))
                   (read-count (read-sequence buffer stream)))
              (when (= read-count count)
                (incf (connection-bytes-received conn) count)
                (setf (connection-last-activity conn) (get-universal-time))
                buffer)))))
    (error ()
      (setf (connection-connected conn) nil)
      nil)))

(defun data-available-p (conn &key (timeout 0))
  "Check if data is available to read on the connection."
  (when (and (connection-socket conn) (connection-connected conn))
    (usocket:wait-for-input (connection-socket conn)
                            :timeout timeout
                            :ready-only t)))
