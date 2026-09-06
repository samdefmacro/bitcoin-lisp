(in-package #:bitcoin-lisp)

(defun %resolve-log-file (log-file data-directory &optional network)
  "The path to log to, or NIL for no file log.

LOG-FILE is -logfile: a path uses it as given, and an explicit \"0\" or \"\"
turns file logging off the way Core's -debuglogfile=0 does. Anything else —
including the usual case of no -logfile at all — is debug.log in NETWORK's
directory under DATA-DIRECTORY.

The NETWORK directory, not the base one. Core resolves -debuglogfile against
GetDataDirNet() (init.cpp, AbsPathForConfigVal), so regtest logs to
<datadir>/regtest/debug.log and only mainnet logs to <datadir>/debug.log. Core's
functional framework reads exactly that path — test_node.py's debug_log_path is
`datadir / chain / \"debug.log\"` — and every assert_debug_log in the suite
goes through it. Writing to the base directory instead does not fail: the
framework opens a file that is not there, finds nothing in it, and reports the
expected message as missing. That is a whole class of tests reporting a
node-behaviour failure for a path bug.

Passing no NETWORK keeps the base directory, which is what the pre-Core callers
and the unit tests expect."
  (flet ((net-dir ()
           (and data-directory
                (let ((dir (uiop:ensure-directory-pathname data-directory)))
                  (if network (network-data-path dir network) dir)))))
    (cond ((and (stringp log-file)
                (or (string= log-file "0") (string= log-file "")))
           nil)
          ;; A RELATIVE -debuglogfile is resolved against the network
          ;; directory, not the process working directory (Core
          ;; AbsPathForConfigVal, net_specific=true). feature_logging.py starts
          ;; a node with -debuglogfile=foo.log and then looks for
          ;; <datadir>/<chain>/foo.log; taken as given it lands wherever the
          ;; node happened to be started from, which for a service is /.
          ((and (stringp log-file) (plusp (length log-file)))
           (let ((path (pathname log-file))
                 (dir (net-dir)))
             (if (and dir (not (eq :absolute (first (pathname-directory path)))))
                 (namestring (merge-pathnames path dir))
                 log-file)))
          (log-file log-file)
          (data-directory
           (let ((dir (net-dir)))
             (namestring (merge-pathnames "debug.log" dir)))))))

;;;; Logging (macros and core functions defined in logging.lisp)

(defun show-logs (&key (n 20) (level :debug))
  "Show the last N log entries at or above LEVEL.
LEVEL can be :debug, :info, :warn, or :error."
  (let ((entries '())
        (min-level (log-level-value level)))
    (bt:with-lock-held (*log-lock*)
      (let ((start (if (< *log-buffer-count* +log-buffer-size+)
                       0
                       *log-buffer-index*)))
        (dotimes (i *log-buffer-count*)
          (let* ((idx (mod (+ start i) +log-buffer-size+))
                 (entry (aref *log-buffer* idx)))
            (when entry
              (push entry entries))))))
    ;; entries is now oldest-first after reverse
    (setf entries (nreverse entries))
    ;; Filter by level and take last n
    (let ((filtered (remove-if-not
                     (lambda (entry)
                       (let ((level-str (and (> (length entry) 22)
                                             (subseq entry 22 (position #\: entry :start 22)))))
                         (when level-str
                           (let ((entry-level (find-symbol (string-upcase (string-trim " " level-str)) :keyword)))
                             (and entry-level
                                  (>= (log-level-value entry-level) min-level))))))
                     entries)))
      (let ((to-show (last filtered n)))
        (format t "~%=== Last ~D Log Entries ===~%" (length to-show))
        (dolist (entry to-show)
          (format t "~A~%" entry))
        (format t "~%")
        (length to-show)))))

(defun clear-logs ()
  "Clear the log buffer."
  (bt:with-lock-held (*log-lock*)
    (dotimes (i +log-buffer-size+)
      (setf (aref *log-buffer* i) nil))
    (setf *log-buffer-index* 0)
    (setf *log-buffer-count* 0))
  t)

(defun enable-console-logging ()
  "Enable logging to the console (REPL)."
  (setf *log-stream* *standard-output*)
  t)

(defun disable-console-logging ()
  "Disable logging to the console. Logs still go to buffer and file."
  (setf *log-stream* nil)
  t)

(defvar *log-file-path* nil
  "Path the file log is currently open on, so SIGHUP can reopen it.")

(defconstant +recent-log-history-bytes+ 10000000
  "Core ShrinkDebugFile's RECENT_DEBUG_HISTORY_SIZE (logging.cpp): the tail
kept when the log file is scrolled at startup.")

(defun shrink-log-file (path)
  "Core's ShrinkDebugFile (logging.cpp): when the log at PATH has grown more
than 10% past RECENT_DEBUG_HISTORY_SIZE, restart the file holding only its last
RECENT_DEBUG_HISTORY_SIZE bytes. Returns T if it scrolled the file.

Runs BEFORE the file is opened for append, so nothing is writing to it while it
is rewritten. Note what this does and does not solve: it bounds the log across
restarts, not within one run — a node that stays up for weeks still grows an
unbounded file. Core's answer to that is the SIGHUP reopen below plus an
external logrotate, and ours is the same."
  (handler-case
      (let ((size (with-open-file (s path :direction :input
                                          :element-type (quote (unsigned-byte 8))
                                          :if-does-not-exist nil)
                    (and s (file-length s)))))
        (when (and size (> size (* 11 (floor +recent-log-history-bytes+ 10))))
          (let ((tail (make-array +recent-log-history-bytes+
                                  :element-type (quote (unsigned-byte 8)))))
            (with-open-file (s path :direction :input
                                    :element-type (quote (unsigned-byte 8)))
              (file-position s (- size +recent-log-history-bytes+))
              (let ((n (read-sequence tail s)))
                (with-open-file (out path :direction :output
                                          :element-type (quote (unsigned-byte 8))
                                          :if-exists :supersede
                                          :if-does-not-exist :create)
                  (write-sequence tail out :end n))))
            t)))
    ;; A log we cannot scroll is not a reason to refuse to start.
    (error (e)
      (format *error-output* "WARNING: could not shrink log file ~A: ~A~%" path e)
      nil)))

(defun start-file-logging (path &key (shrink t))
  "Start logging to a file at PATH, scrolling it first when SHRINK is true and
it has grown past Core's threshold.

SHRINK is Core's -shrinkdebugfile gate, and it is an argument rather than a
global because that is where Core reads it: StartLogging scrolls only when
GetBoolArg(\"-shrinkdebugfile\", DefaultShrinkDebugFile()) is true
(init/common.cpp:108-113), and that default is false whenever any -debug
category is enabled -- an operator reproducing a fault under -debug must not
lose the run before it on the restart that reproduces it."
  (when *log-file-stream*
    (close *log-file-stream*))
  (when shrink
    (shrink-log-file path))
  (setf *log-file-path* path)
  (setf *log-file-stream* (open path :direction :output
                                     :if-exists :append
                                     :if-does-not-exist :create))
  (format t "Logging to file: ~A~%" path)
  path)

(defun reopen-log-file ()
  "Close and reopen the log file at its current path (Core's SIGHUP handler,
which exists so an external logrotate can move the file and have the node
start writing to a fresh one). Without this, the node keeps writing to the
renamed inode and the rotated file grows forever while the new one stays
empty."
  (when *log-file-path*
    (when *log-file-stream*
      (ignore-errors (close *log-file-stream*)))
    (setf *log-file-stream*
          (open *log-file-path* :direction :output
                                :if-exists :append
                                :if-does-not-exist :create))
    t))

(defun install-sighup-log-reopen ()
  "Wire SIGHUP to REOPEN-LOG-FILE, the way Core does for logrotate."
  #+sbcl
  (ignore-errors
   (sb-sys:enable-interrupt
    sb-unix:sighup
    (lambda (&rest ignored)
      (declare (ignore ignored))
      (ignore-errors (reopen-log-file))))
   t))

(defun stop-file-logging ()
  "Stop logging to file."
  (when *log-file-stream*
    (close *log-file-stream*)
    (setf *log-file-stream* nil))
  (setf *log-file-path* nil)
  t)
