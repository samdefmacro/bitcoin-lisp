(in-package #:bitcoin-lisp.tests)

;;;; Core src/test/fuzz/socks5.cpp at the pin: the SOCKS5 client handshake
;;;; against a proxy whose every reply byte is the fuzzer's (Core's
;;;; FuzzedSock). Ours is SOCKS5-CONNECT over a loopback socket whose far end
;;;; writes the buffer's bytes, half-closes, and reads whatever the client
;;;; sends until the client hangs up -- so every read the client makes past
;;;; the buffer ends in an EOF, not a wait.
;;;;
;;;; Core asserts only that Socks5() returns. Beside that, the outcome is
;;;; checked against Core's own reading of the same bytes (netbase.cpp:392-520,
;;;; restated in %SOCKS5-REFERENCE-VERDICT): the handshake succeeds exactly
;;;; when Core's would, and otherwise fails with SOCKS5-ERROR, never another
;;;; condition.

(def-suite :fuzz-socks5-tests :in :bitcoin-lisp-tests
  :description "Core fuzz socks5.cpp over our SOCKS5 client")

(in-suite :fuzz-socks5-tests)

(defun call-with-scripted-peer (reply fn)
  "Call FN with a usocket connected to a loopback peer that sends REPLY, shuts
its write side, and drains what FN's side sends until it hangs up; return
FN's values. The peer thread is joined before this returns."
  (let* ((listener (usocket:socket-listen "127.0.0.1" 0 :element-type '(unsigned-byte 8)
                                                        :reuse-address t))
         (port (usocket:get-local-port listener))
         (peer (bt:make-thread
                (lambda ()
                  (handler-case
                      (let ((s (usocket:socket-accept listener :element-type '(unsigned-byte 8))))
                        (unwind-protect
                             (let ((stream (usocket:socket-stream s)))
                               (write-sequence reply stream)
                               (force-output stream)
                               (usocket:socket-shutdown s :output)
                               (loop while (read-byte stream nil nil)))
                          (ignore-errors (usocket:socket-close s))))
                    (error () nil)))
                :name "fuzz-scripted-peer")))
    (unwind-protect
         (let ((client (usocket:socket-connect "127.0.0.1" port :element-type '(unsigned-byte 8)
                                                                :timeout 5)))
           (unwind-protect (funcall fn client)
             (ignore-errors (usocket:socket-close client))))
      (sb-thread:join-thread peer :default nil :timeout 5)
      (ignore-errors (usocket:socket-close listener)))))

(defun %socks5-reference-verdict (reply auth)
  "Whether Core's Socks5() (netbase.cpp:400-512) succeeds on a proxy that
answers REPLY and then nothing: the method reply, the RFC1929 status when
USER/PASS was chosen and offered, the CONNECT reply header, BND.ADDR as its
ATYP sizes it, and BND.PORT."
  (let ((pos 0))
    (flet ((take (n)
             (when (> (+ pos n) (length reply)) (return-from %socks5-reference-verdict nil))
             (prog1 (subseq reply pos (+ pos n)) (incf pos n))))
      (let ((greeting (take 2)))
        (unless (= (aref greeting 0) 5) (return-from %socks5-reference-verdict nil))
        (cond ((and (= (aref greeting 1) 2) auth)
               (unless (equalp (take 2) #(1 0)) (return-from %socks5-reference-verdict nil)))
              ((= (aref greeting 1) 0))
              (t (return-from %socks5-reference-verdict nil))))
      (let ((header (take 4)))
        (unless (and (= (aref header 0) 5) (= (aref header 1) 0) (= (aref header 2) 0))
          (return-from %socks5-reference-verdict nil))
        (case (aref header 3)
          (1 (take 4))
          (4 (take 16))
          (3 (take (aref (take 1) 0)))
          (t (return-from %socks5-reference-verdict nil))))
      (take 2)
      t)))

(defun %fuzz-socks5-reply (fdp auth)
  "A proxy's replies: one draw in four raw bytes; otherwise a well-formed
SOCKS5 exchange for AUTH (method, RFC1929 status, CONNECT reply, BND.ADDR of
a fuzzed ATYP, BND.PORT), half of those with one byte changed or the tail cut."
  (if (zerop (consume-integral-in-range fdp 0 3))
      (consume-random-length-byte-vector fdp 64)
      (let* ((method (if (and auth (consume-bool fdp)) 2 0))
             (atyp (pick-value-in-array fdp '(1 3 4)))
             (out (concatenate '(simple-array (unsigned-byte 8) (*))
                               (vector 5 method)
                               (if (= method 2) (vector 1 0) #())
                               (vector 5 0 0 atyp)
                               (case atyp
                                 (1 (consume-uint256 fdp))
                                 (4 (consume-uint256 fdp))
                                 (t (let ((n (consume-integral-in-range fdp 0 40)))
                                      (concatenate '(simple-array (unsigned-byte 8) (*))
                                                   (vector n) (make-array n :element-type '(unsigned-byte 8)
                                                                            :initial-element 97)))))
                               (vector (consume-integral fdp :u8) (consume-integral fdp :u8)))))
        ;; BND.ADDR above is a whole uint256 for IPv4 and IPv6: trim to 4 or 16.
        (let ((addr-len (case atyp (1 4) (4 16) (t nil))))
          (when addr-len
            (setf out (concatenate '(simple-array (unsigned-byte 8) (*))
                                   (subseq out 0 (+ (if (= method 2) 8 6)))
                                   (subseq out (+ (if (= method 2) 8 6)) (+ (if (= method 2) 8 6) addr-len))
                                   (subseq out (- (length out) 2))))))
        (when (consume-bool fdp)
          (if (consume-bool fdp)
              (setf out (subseq out 0 (consume-integral-in-range fdp 0 (length out))))
              (let ((i (consume-integral-in-range fdp 0 (1- (length out)))))
                (setf (aref out i) (logxor (aref out i) (consume-integral-in-range fdp 1 255))))))
        out)))

(defun %fuzz-proxy-string (fdp max)
  "A string of up to MAX characters (usually short: the length is drawn
first, so a string does not swallow the buffer the proxy's replies come
from); one draw in eight carries a character past Latin-1, which a name from
the command line or bitcoin.conf may."
  (let* ((n (if (zerop (consume-integral-in-range fdp 0 7))
                (consume-integral-in-range fdp 0 max)
                (consume-integral-in-range fdp 0 24)))
         (s (map 'string #'code-char (consume-bytes fdp n))))
    (if (and (plusp (length s)) (zerop (consume-integral-in-range fdp 0 7)))
        (let ((c (copy-seq s)))
          (setf (char c 0) (code-char (consume-integral-in-range fdp #x100 #xd7ff)))
          c)
        s)))

(define-fuzz-target socks5
    (buffer :core "socks5.cpp:30-50" :iterations 150 :max-len 300)
  "The SOCKS5 client handshake with any credentials and destination, against
a proxy whose replies are the buffer's, either completes -- exactly when
Core's Socks5() would complete on the same bytes -- or fails with a
SOCKS5-ERROR, and it never waits once the proxy has nothing more to say."
  (let* ((fdp (make-fuzzed-data-provider buffer))
         (username (%fuzz-proxy-string fdp 300))
         (password (%fuzz-proxy-string fdp 300))
         (auth (consume-bool fdp))
         (destination (%fuzz-proxy-string fdp 300))
         (port (consume-integral fdp :u16))
         (reply (%fuzz-socks5-reply fdp auth))
         (expected (and (<= (length (sb-ext:string-to-octets destination :external-format :utf-8)) 255)
                        (or (not auth)
                            (and (<= (length (sb-ext:string-to-octets username :external-format :utf-8)) 255)
                                 (<= (length (sb-ext:string-to-octets password :external-format :utf-8)) 255))
                            ;; Core checks the credentials' length only once
                            ;; the proxy has chosen USER/PASS.
                            (not (and (>= (length reply) 2) (= (aref reply 0) 5) (= (aref reply 1) 2))))
                        (%socks5-reference-verdict reply auth)))
         (got (call-with-scripted-peer
               reply
               (lambda (socket)
                 (handler-case
                     (bl.net:socks5-connect socket destination port
                                            :username (and auth username)
                                            :password (and auth password)
                                            :timeout 5)
                   (bl.net:socks5-error () :refused))))))
    (fuzz-assert (eq (fuzz-sabotage (eq got t)) (and expected t))
                 "SOCKS5 to ~S (auth ~A) on reply ~A: ~S, Core's reading says ~A"
                 destination auth (bl.crypto:bytes-to-hex reply) got (if expected "success" "failure"))))
