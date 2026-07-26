;;;; agent-eval.lisp — hardened Swank eval client (cl-agent-repl canonical).
;;;;
;;;; Usage:
;;;;   sbcl --script scripts/dev-swank-eval.lisp '(+ 1 2)'
;;;;   printf '(+ 1 2)' | sbcl --script scripts/dev-swank-eval.lisp
;;;;
;;;; Hardened for agent-driven development:
;;;;   - eval timeout -> protocol-level interrupt: the FORM dies, the warm
;;;;     image SURVIVES (raw swank message (:emacs-interrupt t); the existing
;;;;     debug-abort machinery completes the interrupt)
;;;;   - output/result truncation with an explicit marker
;;;;   - typed failures so callers can tell transport problems from code errors
;;;;
;;;; Exit codes:
;;;;   0 ok | 1 lisp error | 2 connection error / usage
;;;;   3 timed out and interrupted | 4 hard hang (interrupt not honored)
;;;;
;;;; Environment:
;;;;   DEV_SWANK_HOST (127.0.0.1)  DEV_SWANK_PORT (4005)
;;;;   DEV_SWANK_PACKAGE (COMMON-LISP-USER)
;;;;   DEV_EVAL_TIMEOUT seconds (20; raise for test suites)
;;;;   DEV_EVAL_GRACE seconds (10)  DEV_EVAL_MAX_OUTPUT chars (10000)

;; Deliberately no ASDF, no Quicklisp, no usocket: the only I/O need is one
;; TCP client connection, which the sb-bsd-sockets contrib covers. Loading
;; Quicklisp+usocket cost ~10s per eval; even (require :asdf) costs seconds
;; here because ASDF's require hook triggers a full source-registry scan of
;; ~/common-lisp// (which contains cloned reference repos). Native SBCL
;; startup keeps each eval call under half a second.
(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :sb-bsd-sockets))

(defun getenv/default (name default)
  (or (sb-ext:posix-getenv name) default))

(defun parse-env-integer (name default)
  (parse-integer (getenv/default name (write-to-string default))))

(defparameter *host* (getenv/default "DEV_SWANK_HOST" "127.0.0.1"))
(defparameter *port* (parse-env-integer "DEV_SWANK_PORT" 4005))
(defparameter *package-name* (getenv/default "DEV_SWANK_PACKAGE" "COMMON-LISP-USER"))
(defparameter *timeout-seconds* (parse-env-integer "DEV_EVAL_TIMEOUT" 20))
(defparameter *grace-seconds* (parse-env-integer "DEV_EVAL_GRACE" 10))
(defparameter *max-output* (parse-env-integer "DEV_EVAL_MAX_OUTPUT" 10000))
(defparameter *max-frames* 10)

(defvar *rex-counter* 0)

(defun read-stdin-all ()
  (with-output-to-string (out)
    (loop for line = (read-line *standard-input* nil nil)
          while line
          do (write-string line out)
             (terpri out))))

(defun command-expression ()
  ;; --script mode: *posix-argv* is ("sbcl" USER-ARGS...) with lisp options
  ;; and the script path already consumed.
  (let ((args (cdr sb-ext:*posix-argv*)))
    (if args
        (format nil "~{~A~^ ~}" args)
        (string-trim '(#\Space #\Tab #\Newline #\Return) (read-stdin-all)))))

(defun truncate-output (string)
  (if (> (length string) *max-output*)
      (concatenate 'string (subseq string 0 *max-output*)
                   (format nil "~%...[TRUNCATED: output exceeded ~D chars]~%" *max-output*))
      string))

(defun deadline-after (seconds)
  (+ (get-internal-real-time) (* seconds internal-time-units-per-second)))

(defun seconds-remaining (deadline)
  (/ (- deadline (get-internal-real-time)) internal-time-units-per-second))

;;; Swank wire protocol

(defun swank-read-message (stream)
  (let ((header (make-string 6)))
    (read-sequence header stream)
    (let* ((len (parse-integer header :radix 16))
           (payload (make-string len)))
      (read-sequence payload stream)
      (handler-case (read-from-string payload)
        (error ()
          (let ((start (position #\: payload)))
            (if start
                (let ((end (position-if
                            (lambda (c) (member c '(#\Space #\) #\Newline)))
                            payload :start (1+ start))))
                  (list (intern (string-upcase (subseq payload (1+ start) end))
                                :keyword)))
                (list :unknown-message))))))))

(defun swank-send-raw (stream fmt &rest args)
  (let* ((payload (apply #'format nil fmt args))
         (header (format nil "~6,'0X" (length payload))))
    (write-string header stream)
    (write-string payload stream)
    (force-output stream)))

;; LISTEN covers both buffered characters and fd readability on SBCL socket
;; streams; 50ms polling granularity is imperceptible for a CLI tool. Only the
;; clock decides the deadline — a spurious wakeup is never a timeout.
(defun wait-readable (stream deadline)
  (loop
    (when (listen stream)
      (return t))
    (when (<= (seconds-remaining deadline) 0)
      (return nil))
    (sleep 0.05)))

;;; Reporting

(defun report-connection-error (condition)
  (format *error-output*
          "CONNECTION-ERROR: cannot reach Swank at ~A:~D (~A).~%~
           The dev image is not reachable — this is NOT an error in your code.~%~
           Check it first: scripts/dev.sh status  (start with: scripts/dev.sh start)~%"
          *host* *port* condition)
  (sb-ext:exit :code 2))

(defun report-lisp-error (description frames)
  (format *error-output* "LISP-ERROR: ~A~%" (truncate-output (or description "unknown error")))
  (when frames
    (format *error-output* "Backtrace (top ~D frames):~%" (length frames))
    (dolist (frame frames)
      (format *error-output* "  ~A~%" frame)))
  (sb-ext:exit :code 1))

(defun report-timeout ()
  (format *error-output*
          "TIMEOUT: form exceeded ~Ds and was interrupted. The image SURVIVED;~%~
           state changes made before the interrupt may have taken effect.~%~
           For long-running forms (test suites), raise DEV_EVAL_TIMEOUT.~%"
          *timeout-seconds*)
  (sb-ext:exit :code 3))

(defun report-hard-hang ()
  (format *error-output*
          "HARD-HANG: interrupt was not honored within ~Ds grace. The eval is~%~
           stuck (likely in foreign code or with interrupts deferred). The image~%~
           may need a restart: scripts/dev.sh stop && scripts/dev.sh start~%"
          *grace-seconds*)
  (sb-ext:exit :code 4))

;;; Main eval loop

(defun connect-or-die (host port)
  (handler-case
      (let ((socket (make-instance 'sb-bsd-sockets:inet-socket
                                   :type :stream :protocol :tcp)))
        (sb-bsd-sockets:socket-connect
         socket (sb-bsd-sockets:make-inet-address host) port)
        (values socket
                (sb-bsd-sockets:socket-make-stream
                 socket :input t :output t
                 :element-type 'character
                 :external-format :utf-8
                 :buffering :full)))
    (error (e) (report-connection-error e))))

(defun extract-frames (debug-msg)
  ;; (:debug thread level (desc type . extras) restarts frames conts)
  (let ((frames (sixth debug-msg)))
    (when (listp frames)
      (loop for f in frames
            for i from 0 below *max-frames*
            when (and (listp f) (stringp (second f)))
              collect (second f)))))

(defun swank-eval (expression)
  (multiple-value-bind (socket stream) (connect-or-die *host* *port*)
    (swank-eval-1 socket stream expression)))

(defun swank-eval-1 (socket stream expression)
  (let* ((id (incf *rex-counter*))
         (deadline (deadline-after *timeout-seconds*))
         (interrupted nil)
         (output-parts '())
         (error-description nil)
         (error-frames nil)
         (abort-restart-index nil))
    (unwind-protect
         (progn
           (swank-send-raw stream
                           "(:emacs-rex (swank:eval-and-grab-output ~S) ~S t ~D)"
                           expression *package-name* id)
           (loop
             (unless (wait-readable stream deadline)
               (if interrupted
                   (report-hard-hang)
                   (progn
                     (setf interrupted t)
                     (swank-send-raw stream "(:emacs-interrupt t)")
                     (setf deadline (deadline-after *grace-seconds*)))))
             (when (listen stream)
               (let ((msg (swank-read-message stream)))
                 (case (first msg)
                   (:return
                    (when (eql (third msg) id)
                      (let ((value (second msg)))
                        (case (first value)
                          (:ok
                           (let ((stdout (first (second value)))
                                 (result (second (second value))))
                             (return (values result
                                             (apply #'concatenate 'string
                                                    (nreverse (cons stdout output-parts)))))))
                          (:abort
                           (cond (interrupted (report-timeout))
                                 (t (report-lisp-error
                                     (or error-description
                                         (format nil "Aborted: ~A" (second value)))
                                     error-frames))))
                          (otherwise
                           (report-lisp-error (format nil "Unexpected return: ~S" value) nil))))))
                   (:debug
                    (let ((condition (fourth msg))
                          (restarts (fifth msg)))
                      (when (and condition (listp condition) (stringp (first condition)))
                        (setf error-description (first condition)))
                      (setf error-frames (extract-frames msg))
                      (setf abort-restart-index
                            (position-if
                             (lambda (r)
                               (and (listp r) (stringp (first r))
                                    (member (first r) '("*ABORT" "ABORT") :test #'string=)))
                             restarts))))
                   (:debug-activate
                    (let* ((thread (second msg))
                           (level (third msg))
                           (abort-id (incf *rex-counter*))
                           (restart-idx (or abort-restart-index 1)))
                      (swank-send-raw stream
                                      "(:emacs-rex (swank:invoke-nth-restart-for-emacs ~D ~D) ~S ~D ~D)"
                                      level restart-idx *package-name* thread abort-id)))
                   (:write-string
                    (push (second msg) output-parts))
                   (:read-string
                    (let ((thread (second msg))
                          (tag (third msg)))
                      (swank-send-raw stream
                                      "(:emacs-return-string ~D ~D \"~A\")"
                                      thread tag (string #\Newline))))
                   (:ping
                    (swank-send-raw stream "(:emacs-pong ~D ~D)" (second msg) (third msg)))
                   (otherwise nil))))))
      (ignore-errors (sb-bsd-sockets:socket-close socket)))))

(let ((expression (command-expression)))
  (when (zerop (length expression))
    (format *error-output* "No expression supplied~%")
    (sb-ext:exit :code 2))
  (multiple-value-bind (result output) (swank-eval expression)
    (when (plusp (length output))
      (write-string (truncate-output output)))
    (when (plusp (length result))
      (format t "~&~A~%" (truncate-output result)))))
