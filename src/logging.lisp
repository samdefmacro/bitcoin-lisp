(in-package #:bitcoin-lisp)

;;;; Logging
;;;;
;;;; Logging infrastructure for the Bitcoin node.
;;;; This file must be loaded before any modules that use log-debug/log-info/etc.

(defvar *log-stream* nil
  "Stream for log output. NIL means logs only go to buffer.")

(defvar *log-file-stream* nil
  "File stream for log output, if logging to file.")

(defvar *log-levels*
  '(:debug 0 :info 1 :warn 2 :error 3)
  "Log level priority values.")

(defvar *current-log-level* :info
  "Current log level threshold. Set by start-node.")

(defconstant +log-buffer-size+ 500
  "Maximum number of log entries to keep in memory.")

(defvar *log-buffer* (make-array +log-buffer-size+ :initial-element nil)
  "Ring buffer for recent log messages.")

(defvar *log-buffer-index* 0
  "Current write position in log buffer.")

(defvar *log-buffer-count* 0
  "Number of entries in log buffer.")

(defvar *log-buffer-lock* (bt:make-lock "log-buffer-lock")
  "Lock for thread-safe log buffer access.")

(defun log-level-value (level)
  "Get numeric value for log LEVEL."
  (getf *log-levels* level 1))

(defun format-log-entry (level format-string args)
  "Format a log entry and return the string."
  (let ((timestamp (multiple-value-bind (sec min hour day month year)
                       (get-decoded-time)
                     (format nil "~4,'0D-~2,'0D-~2,'0D ~2,'0D:~2,'0D:~2,'0D"
                             year month day hour min sec))))
    (format nil "[~A] ~A: ~?"
            timestamp
            (string-upcase (symbol-name level))
            format-string args)))

(defun add-to-log-buffer (entry)
  "Add a log entry to the ring buffer."
  (bt:with-lock-held (*log-buffer-lock*)
    (setf (aref *log-buffer* *log-buffer-index*) entry)
    (setf *log-buffer-index* (mod (1+ *log-buffer-index*) +log-buffer-size+))
    (when (< *log-buffer-count* +log-buffer-size+)
      (incf *log-buffer-count*))))

(defun node-log (level format-string &rest args)
  "Log a message at LEVEL."
  (when (>= (log-level-value level)
            (log-level-value *current-log-level*))
    (let ((entry (format-log-entry level format-string args)))
      ;; Always add to buffer
      (add-to-log-buffer entry)
      ;; Write to console if *log-stream* is set
      (when *log-stream*
        (format *log-stream* "~A~%" entry)
        (finish-output *log-stream*))
      ;; Write to file if logging to file
      (when *log-file-stream*
        (format *log-file-stream* "~A~%" entry)
        (finish-output *log-file-stream*)))))

(defmacro log-debug (format-string &rest args)
  `(node-log :debug ,format-string ,@args))

(defmacro log-info (format-string &rest args)
  `(node-log :info ,format-string ,@args))

(defmacro log-warn (format-string &rest args)
  `(node-log :warn ,format-string ,@args))

(defmacro log-error (format-string &rest args)
  `(node-log :error ,format-string ,@args))
