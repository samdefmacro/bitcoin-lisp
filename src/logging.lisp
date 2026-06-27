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

(defun %log-emit (level format-string args)
  "Format and write a log ENTRY unconditionally (buffer + console + file)."
  (let ((entry (format-log-entry level format-string args)))
    (add-to-log-buffer entry)
    (when *log-stream*
      (format *log-stream* "~A~%" entry)
      (finish-output *log-stream*))
    (when *log-file-stream*
      (format *log-file-stream* "~A~%" entry)
      (finish-output *log-file-stream*))))

(defun node-log (level format-string &rest args)
  "Log a message at LEVEL."
  (when (>= (log-level-value level)
            (log-level-value *current-log-level*))
    (%log-emit level format-string args)))

;;;; Per-category debug logging (Bitcoin Core's -debug / logging RPC)
;;;;
;;;; Orthogonal to the level threshold above: a category-tagged debug message is
;;;; emitted when its category is enabled (via the logging RPC) OR when the global
;;;; level already includes :debug. So enabling a category surfaces just that
;;;; subsystem's debug output without flipping the whole node to :debug, and a
;;;; node already at :debug is unchanged.

(defparameter +log-categories+
  '("net" "tor" "mempool" "http" "bench" "zmq" "walletdb" "rpc" "estimatefee"
    "addrman" "selectcoins" "reindex" "cmpctblock" "rand" "prune" "proxy"
    "mempoolrej" "libevent" "coindb" "qt" "leveldb" "validation" "ipc" "lock"
    "blockstorage" "txreconciliation" "scan" "txpackages" "kernel" "privatebroadcast")
  "Debug logging categories, matching Bitcoin Core's LogCategories (logging.cpp).")

(defvar *debug-categories* (make-hash-table :test 'equal)
  "Set of currently-enabled debug log categories (category-string -> T).")

(defun log-category-known-p (category)
  (and (stringp category) (member category +log-categories+ :test #'string=)))

(defun log-category-enabled-p (category)
  "T if debug logging for CATEGORY (a string) is currently enabled."
  (and (gethash category *debug-categories*) t))

(defun %log-category-all-p (category)
  "T if CATEGORY denotes all categories (Core GetLogCategory: \"\"/\"1\"/\"all\")."
  (and (stringp category)
       (or (string= category "") (string= category "1") (string= category "all"))))

(defun enable-log-category (category)
  "Enable CATEGORY (or every category for \"\"/\"1\"/\"all\"). Returns T on
success, NIL if CATEGORY is unknown (Bitcoin Core EnableCategory)."
  (cond ((%log-category-all-p category)
         (dolist (c +log-categories+ t) (setf (gethash c *debug-categories*) t)))
        ((log-category-known-p category)
         (setf (gethash category *debug-categories*) t) t)
        (t nil)))

(defun disable-log-category (category)
  "Disable CATEGORY (or every category for \"\"/\"1\"/\"all\"). Returns T on
success, NIL if CATEGORY is unknown (Bitcoin Core DisableCategory)."
  (cond ((%log-category-all-p category) (clrhash *debug-categories*) t)
        ((log-category-known-p category) (remhash category *debug-categories*) t)
        (t nil)))

(defun node-log-category (category format-string &rest args)
  "Emit a :debug entry tagged with CATEGORY iff that category is enabled, or the
global level already includes :debug."
  (when (or (log-category-enabled-p category)
            (>= (log-level-value :debug) (log-level-value *current-log-level*)))
    (%log-emit :debug format-string args)))

(defmacro log-cat (category format-string &rest args)
  "Debug-log under CATEGORY (a string): shown only when that category is enabled
via the logging RPC (or the node is globally at :debug)."
  `(node-log-category ,category ,format-string ,@args))

(defmacro log-debug (format-string &rest args)
  `(node-log :debug ,format-string ,@args))

(defmacro log-info (format-string &rest args)
  `(node-log :info ,format-string ,@args))

(defmacro log-warn (format-string &rest args)
  `(node-log :warn ,format-string ,@args))

(defmacro log-error (format-string &rest args)
  `(node-log :error ,format-string ,@args))
