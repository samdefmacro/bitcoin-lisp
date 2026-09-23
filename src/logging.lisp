(defpackage #:bitcoin-lisp.logging
  (:documentation "The node's log: levels, categories (Core -debug), the
in-memory ring buffer, the file stream, the rate limiter, the lines deferred
from before the log file exists, and the -*notify shell hooks. A layer of
its own (bitcoin-lisp/logging): nothing above the util layer exists while it
compiles. BITCOIN-LISP :USEs it and re-exports the entry points, so every
caller keeps writing log-info (or the bl-prefixed spelling) unchanged.")
  (:use #:cl #:bitcoin-lisp.conditions)
  (:local-nicknames (#:bt #:bordeaux-threads))
  (:export
   #:*category-log-levels*
   #:*current-log-level*
   #:*deferred-log-lines*
   #:*log-buffer*
   #:*log-buffer-count*
   #:*log-buffer-index*
   #:*log-file-stream*
   #:*log-lock*
   #:*log-rate-limit*
   #:*log-rate-locations*
   #:*log-rate-window-start*
   #:log-rate-limiter-tick
   #:*log-stream*
   #:*log-suppressions-active*
   #:*log-ips*
   #:*log-thread-names*
   #:*alert-notify-command*
   #:*client-version-is-release*
   #:*log-time-micros*
   #:+log-buffer-size+
   #:+log-categories+
   #:apply-log-categories
   #:default-shrink-debug-file-p
   #:category-log-level
   #:clear-category-log-levels
   #:defer-log
   #:disable-log-category
   #:enable-log-category
   #:flush-deferred-log-lines
   #:log-cat
   #:log-category-enabled-p
   #:log-category-known-p
   #:log-debug
   #:log-error
   #:log-info
   #:log-ip
   #:log-level-value
   #:log-warn
   #:node-log
   #:reset-warnings
   #:run-notify-command
   #:report-init-error
   #:*fatal-error-shutdown-function*
   #:fatal-error
   #:set-kernel-warning
   #:set-warning
   #:trace-thread
   #:unset-warning
   #:warnings-for-rpc
   #:set-category-log-level))

(eval-when (:compile-toplevel :load-toplevel :execute)
  (bitcoin-lisp.nicknames:install-package-nicknames))

(in-package #:bitcoin-lisp.logging)

;;;; Logging
;;;;
;;;; Logging infrastructure for the Bitcoin node.
;;;; Loaded (as its own ASDF system) before any module that logs.

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

(defvar *log-lock* (bt:make-lock "log-lock")
  "Guards the WHOLE emit — ring buffer, console stream and file stream — not
just the buffer it used to be named for. Core holds one mutex
(BCLog::Logger::m_cs) across all of LogPrintStr for exactly this reason: with
only the buffer locked, lines from the ~8 threads that log interleave mid-line
in the very file the node's wedges are diagnosed from.

PLAIN, as Core's StdMutex is. It was recursive for one release because our
SIGTERM/SIGINT handler logged, so a signal delivered to a thread already inside
an emit would deadlock on its own lock. The handler is now what Core's is — an
atomic flag plus a one-byte self-pipe write, nothing else (node/shutdown.lisp
%HANDLE-STOP-SIGNAL) — so no emit can re-enter another, and a recursive lock
would only hide a future one.")

(defun log-level-value (level)
  "Get numeric value for log LEVEL."
  (getf *log-levels* level 1))

(defun %log-escape-message (string)
  "Core BCLog::LogEscapeMessage (logging.cpp:329-340): pass printable characters
and newline through, render every other control character — and DEL — as
\\xNN. Peer-supplied text (a subversion string, a rejection reason) and
condition reports both reach the log, and either can otherwise smuggle a
carriage return or a terminal escape sequence into a file an operator reads."
  (flet ((plainp (ch)
           (let ((c (char-code ch)))
             (and (or (>= c 32) (= c 10)) (/= c 127)))))
    (if (every #'plainp string)
        string
        (with-output-to-string (out)
          (loop for ch across string
                do (if (plainp ch)
                       (write-char ch out)
                       (format out "\\x~(~2,'0X~)" (char-code ch))))))))

(defun log-level-name (level)
  "Core's spelling of LEVEL (BCLog::Logger::LogLevelToStr, logging.cpp:234).
Note :WARN prints as \"warning\" — the functional tests match on Core's word."
  (ecase level
    (:trace "trace")
    (:debug "debug")
    (:info "info")
    (:warn "warning")
    (:error "error")))

(defun log-category-level-prefix (category level)
  "Core's `[category:level] ` tag for a log line, or \"\" where Core prints none
 (BCLog::LogPrefix, logging.cpp:343-367).

Three rules, all Core's, and all load-bearing for the functional tests, which
match on the rendered line:

- An UNCATEGORIZED INFO line gets NO tag at all. That is the common case, so
  most lines lose the `INFO: ` this used to print.
- A CATEGORIZED DEBUG line is tagged with the category alone — `[net] ` — since
  a category implies debug. Categories were dropped entirely before this; every
  `log-cat` line came out as a bare debug line with no way to tell which
  subsystem wrote it.
- Anything else is `[level] ` or `[category:level] `, with :WARN spelled
  Core's way."
  (let* ((has-category (and category (stringp category)
                            (plusp (length category))
                            (not (string= category "all")))))
    (cond ((and (not has-category) (eq level :info)) "")
          (t (format nil "[~@[~A~]~:[~;~:*~A~]] "
                     (and has-category category)
                     (unless (and has-category (eq level :debug))
                       (concatenate 'string (if has-category ":" "")
                                    (log-level-name level))))))))

(defconstant +unix-epoch-universal-time+ 2208988800
  "Universal time at the unix epoch. Spelled here rather than taken from
BL.SER because the logging system loads long before serialization does.")

(defun %log-timestamp ()
  "The line's timestamp, from ONE reading of the wall clock.

Core's LogTimestampStr formats a single GetTime<microseconds>()
(FormatISO8601DateTime, logging.cpp), so its seconds and its microseconds
cannot disagree. Ours took the date and seconds from GET-DECODED-TIME and the
microseconds from GET-INTERNAL-REAL-TIME -- a process-relative counter with no
relation to the wall clock, whose fraction is therefore uniform noise inside
any given second. Consecutive lines ran backwards: a functional-test node's
debug.log on 2026-09-19 has `03:05:04.964001' immediately followed by
`03:05:04.021000'. debug.log is read in order, by people and by the test
framework's assert_debug_log alike.

GET-TIME-OF-DAY is gettimeofday(2): both halves come out of it together."
  (multiple-value-bind (unix-sec usec)
      #+sbcl (sb-ext:get-time-of-day)
      #-sbcl (values (- (get-universal-time) +unix-epoch-universal-time+) 0)
    (multiple-value-bind (sec min hour day month year)
        (decode-universal-time (+ unix-sec +unix-epoch-universal-time+))
      (if *log-time-micros*
          ;; Core's -logtimemicros appends .%06d.
          (format nil "~4,'0D-~2,'0D-~2,'0D ~2,'0D:~2,'0D:~2,'0D.~6,'0D"
                  year month day hour min sec usec)
          (format nil "~4,'0D-~2,'0D-~2,'0D ~2,'0D:~2,'0D:~2,'0D"
                  year month day hour min sec)))))

(defun format-log-entry (level format-string args &optional category)
  "Format a log entry and return the string.

*PRINT-PRETTY* is bound OFF. With it on, a `~A' of a multi-line object — an
SBCL condition report is the common case — is laid out relative to the CURRENT
column, so a type error appended to the end of a log line comes out as ten lines
indented under it, with the first word alone on the first line. That is exactly
how the fd>1023 select() failure reported itself on mainnet (2026-08-18): the
diagnostic written to catch it logged `... with a non-I/O error: The' and put
`value 3119 is not of type (UNSIGNED-BYTE 10)' in nine further lines, so a grep
for the message returned nothing usable."
  (let ((timestamp (%log-timestamp)))
    (%log-escape-message
     (let ((*print-pretty* nil))
       (format nil "[~A] ~@[[~A] ~]~A~?"
               timestamp
               (when *log-thread-names*
                 (ignore-errors (bt:thread-name (bt:current-thread))))
               (log-category-level-prefix category level)
               format-string args)))))

(defun add-to-log-buffer (entry)
  "Add a log entry to the ring buffer."
  (bt:with-lock-held (*log-lock*)
    (%add-to-log-buffer-locked entry)))

(defun %add-to-log-buffer-locked (entry)
  "Ring-buffer insert with *LOG-LOCK* already held."
  (setf (aref *log-buffer* *log-buffer-index*) entry)
  (setf *log-buffer-index* (mod (1+ *log-buffer-index*) +log-buffer-size+))
  (when (< *log-buffer-count* +log-buffer-size+)
    (incf *log-buffer-count*)))

;;;; Log rate limiting (Core BCLog::LogRateLimiter, logging.h:63-124,
;;;; logging.cpp:376-583)
;;;;
;;;; A fixed window per source location: each may write RATELIMIT_MAX_BYTES to
;;;; disk per window, after which that location alone is suppressed until the
;;;; window resets. Core's stated purpose is that no inbound peer can fill an
;;;; operator's disk with debug.log entries; ours is also that no single benign
;;;; condition can crowd out the log. Measured 2026-08-20 on the live testnet4
;;;; node: one self-resolving header rejection accounted for 33,567 of 141,693
;;;; lines.
;;;;
;;;; Core keys the window on __func__ plus file and line. We have no source
;;;; location at the call site, so the FORMAT STRING is the key — it is a
;;;; literal at every call site in this tree, so it identifies the site just as
;;;; stably, and it survives inlining, which a line number would not.

(defconstant +log-ratelimit-max-bytes+ (* 1024 1024)
  "Bytes a single log location may write to disk per window (Core
RATELIMIT_MAX_BYTES).")

(defconstant +log-ratelimit-window-seconds+ 3600
  "Window after which every location's budget resets (Core RATELIMIT_WINDOW).")

(defvar *log-rate-limit* t
  "Rate-limit :info and louder (Core DEFAULT_LOGRATELIMIT / -logratelimit).")

(defstruct (log-rate-stats (:constructor make-log-rate-stats ()))
  "Remaining and dropped byte counts for one log location (Core
LogRateLimiter::Stats)."
  (available-bytes +log-ratelimit-max-bytes+ :type (integer 0))
  (dropped-bytes 0 :type (integer 0)))

(defvar *log-rate-locations* (make-hash-table :test 'equal)
  "Format string -> LOG-RATE-STATS for the current window.")

(defvar *log-rate-window-start* 0
  "Universal time the current rate-limit window opened.")

(defvar *log-suppressions-active* nil
  "T while any location is suppressed. Core prefixes every line with \"[*] \"
in this state so a reader debugging an issue is not misled by the gap.")

(defun %log-rate-consume (key nbytes)
  "Charge NBYTES to KEY's budget and return :UNSUPPRESSED, :NEWLY-SUPPRESSED or
:STILL-SUPPRESSED (Core LogRateLimiter::Consume + Stats::Consume). Caller holds
*LOG-LOCK*.

Callers pass the entry's CHARACTER count where Core passes its byte count; on a
1 MiB budget the difference only matters for non-ASCII text, and measuring the
UTF-8 length would mean encoding every log line twice."
  (let* ((stats (or (gethash key *log-rate-locations*)
                    (setf (gethash key *log-rate-locations*)
                          (make-log-rate-stats))))
         (status (if (plusp (log-rate-stats-dropped-bytes stats))
                     :still-suppressed
                     :unsuppressed)))
    (cond ((> nbytes (log-rate-stats-available-bytes stats))
           (incf (log-rate-stats-dropped-bytes stats) nbytes)
           (setf (log-rate-stats-available-bytes stats) 0)
           (when (eq status :unsuppressed)
             (setf status :newly-suppressed
                   *log-suppressions-active* t)))
          (t
           (decf (log-rate-stats-available-bytes stats) nbytes)))
    status))

(defun %log-maybe-reset-window ()
  "Close an elapsed window, reporting what each suppressed location dropped
(Core LogRateLimiter::Reset). Core drives this from the scheduler on the
window boundary, and so does a running node here (LOG-RATE-LIMITER-TICK from
the scheduler thread); the next emit also closes an elapsed window, so an
image without that thread loses only promptness -- the byte counts the notices
carry are the same. Caller holds *LOG-LOCK*."
  (let ((now (get-universal-time)))
    (when (>= (- now *log-rate-window-start*) +log-ratelimit-window-seconds+)
      (let ((dropped '()))
        (maphash (lambda (key stats)
                   (when (plusp (log-rate-stats-dropped-bytes stats))
                     (push (cons key (log-rate-stats-dropped-bytes stats)) dropped)))
                 *log-rate-locations*)
        (clrhash *log-rate-locations*)
        ;; Reopen the window BEFORE emitting, or each notice re-enters this
        ;; function against the window it is reporting on.
        (setf *log-rate-window-start* now
              *log-suppressions-active* nil)
        (dolist (cell dropped)
          (%log-emit-locked
           :warn "Restarting logging from ~S: ~D bytes were dropped during the last ~Ds."
           (list (car cell) (cdr cell) +log-ratelimit-window-seconds+)
           nil))))))

(defun log-rate-limiter-tick ()
  "The scheduler's call into the log rate limiter (Core schedules
LogRateLimiter::Reset every window, init.cpp:1475-1479): close the window once
it has elapsed."
  (when *log-rate-limit*
    (bt:with-lock-held (*log-lock*)
      (%log-maybe-reset-window))))

(defun %log-emit-locked (level format-string args ratelimit &optional category)
  "Emit one entry with *LOG-LOCK* held (Core LogPrintStr_, which is likewise the
lock-held, self-recursive half of the pair). RATELIMIT nil is Core's
should_ratelimit=false: used for the limiter's own notices, which must never be
suppressed by the limiter."
  (let ((entry (format-log-entry level format-string args category))
        (to-file t))
    (when (and ratelimit *log-rate-limit*)
      (%log-maybe-reset-window)
      (ecase (%log-rate-consume format-string (length entry))
        (:unsuppressed)
        ;; The entry that trips the limit is still written — Core's notice ends
        ;; "Last log entry." for that reason.
        (:newly-suppressed
         (%log-emit-locked
          :warn
          "Excessive logging detected from ~S: >~D bytes logged during the last time window of ~Ds. Suppressing logging to disk from this source location until time window resets. Console logging unaffected. Last log entry."
          (list format-string +log-ratelimit-max-bytes+ +log-ratelimit-window-seconds+)
          nil))
        (:still-suppressed (setf to-file nil))))
    (let ((line (if *log-suppressions-active*
                    (concatenate 'string "[*] " entry)
                    entry)))
      (%add-to-log-buffer-locked line)
      (when *log-stream*
        (format *log-stream* "~A~%" line)
        (finish-output *log-stream*))
      ;; Suppression is disk-only; Core says so in the notice it prints.
      (when (and to-file *log-file-stream*)
        (format *log-file-stream* "~A~%" line)
        (finish-output *log-file-stream*)))))

(defun %log-emit (level format-string args &optional (ratelimit t) category)
  "Format and write a log ENTRY unconditionally (buffer + console + file)."
  (bt:with-lock-held (*log-lock*)
    (%log-emit-locked level format-string args ratelimit category)))

(defun node-log (level format-string &rest args)
  "Log a message at LEVEL.

Rate-limited from :info upward, exactly Core's split: LogInfo/LogWarning/
LogError pass should_ratelimit=true because they log unconditionally, while
LogDebug/LogTrace pass false — \"users specifying -debug are assumed to be
developers or power users who are aware that -debug may cause excessive disk
usage\" (util/log.h:91-113)."
  (when (>= (log-level-value level)
            (log-level-value *current-log-level*))
    (%log-emit level format-string args
               (>= (log-level-value level) (log-level-value :info)))))

;;;; Per-category debug logging (Bitcoin Core's -debug / logging RPC)
;;;;
;;;; Orthogonal to the level threshold above: a category-tagged debug message is
;;;; emitted when its category is enabled (via the logging RPC) OR when the global
;;;; level already includes :debug. So enabling a category surfaces just that
;;;; subsystem's debug output without flipping the whole node to :debug, and a
;;;; node already at :debug is unchanged.

(alexandria:define-constant +log-categories+
  '("net" "tor" "mempool" "http" "bench" "zmq" "walletdb" "rpc" "estimatefee"
    "addrman" "selectcoins" "reindex" "cmpctblock" "rand" "prune" "proxy"
    "mempoolrej" "libevent" "coindb" "qt" "leveldb" "validation" "i2p" "ipc" "lock"
    "blockstorage" "txreconciliation" "scan" "txpackages" "kernel" "privatebroadcast")
  :test #'equalp :documentation "Debug logging categories, matching Bitcoin Core's LogCategories (logging.cpp).")

(defvar *debug-categories* (make-hash-table :test 'equal)
  "Set of currently-enabled debug log categories (category-string -> T).")

(defvar *category-log-levels* (make-hash-table :test 'equal :synchronized t)
  "category -> the level threshold for that category alone (Core
-loglevel=<category>:<level>, BCLog::Logger::SetCategoryLogLevel).

Separate from *DEBUG-CATEGORIES*, which is -debug and answers whether this
category is on at all. This answers how verbose it is, and a category with an
entry here is emitted at that level whether or not -debug named it — which is
Core's behaviour and the point of having both options.

SYNCHRONIZED: written once at start-up and by the logging RPC, read from every
thread that logs.")

(defun category-log-level (category)
  "CATEGORY's own threshold, or NIL when it has none."
  (and category (gethash category *category-log-levels*)))

(defun set-category-log-level (category level)
  "Give CATEGORY its own threshold. Returns NIL for an unknown category, which
is what makes -loglevel=<bad>:<level> a fatal init error rather than a typo the
operator never hears about."
  (when (log-category-known-p category)
    (setf (gethash category *category-log-levels*) level)
    t))

(defun clear-category-log-levels ()
  (clrhash *category-log-levels*))

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
         (setf (gethash category *debug-categories*) t) t)))

(defun disable-log-category (category)
  "Disable CATEGORY (or every category for \"\"/\"1\"/\"all\"). Returns T on
success, NIL if CATEGORY is unknown (Bitcoin Core DisableCategory)."
  (cond ((%log-category-all-p category) (clrhash *debug-categories*) t)
        ((log-category-known-p category) (remhash category *debug-categories*) t)))

(defvar *log-time-micros* nil
  "Timestamp log lines to microseconds (Core -logtimemicros).")

(defvar *log-thread-names* nil
  "Prefix each log line with the writing thread's name (Core -logthreadnames).
Core prints it as [threadname] after the timestamp.")

(defvar *log-ips* nil
  "Include peer addresses in log output (Core fLogIPs, logging.h:35 and
logging.cpp:47, set from -logips with DEFAULT_LOGIPS false, logging.h:28 and
init/common.cpp:34,57).

Default OFF, and that default is the privacy model: debug.log is the file an
operator attaches to a bug report, hands to support and keeps in backups, so
Core made the record of who connected to the node opt-in. Every routine
per-peer line names the peer by its numeric id and reaches its address only
through LOG-IP.")

(defun log-ip (address)
  "Core CNode::LogIP (net.cpp:704-707): \" peeraddr=<address>\" when *LOG-IPS*
is on, and the empty string otherwise -- the leading space included, so a caller
appends it to a line that already ends in peer=<id> and gets Core's spacing
either way.

ADDRESS may be NIL (a peer reaped before its address was recorded); that is the
empty string too, not \" peeraddr=NIL\"."
  (if (and *log-ips* address)
      (format nil " peeraddr=~A" address)
      ""))

(defun apply-log-categories (include exclude)
  "Enable the categories in INCLUDE and then disable those in EXCLUDE, the order
Core applies them in (-debug then -debugexclude, init/common.cpp). Signals on an
unknown name — Core logs a warning there, but a silently-ignored -debug=nett is
an operator staring at a log that will never contain what they asked for.

\"1\", \"all\" and the empty string (a bare -debug) enable everything; \"0\" and
\"none\" disable everything, and Core lets a later -debug re-enable after them."
  ;; Everything before the LAST -debug=0/none is disregarded entirely, invalid
  ;; names included (Core SetLoggingCategories, init/common.cpp:82-88: it finds
  ;; the last negation and processes only the tail from it). Validating the
  ;; whole list made `-debug=abc -debug=none -debug=net` a fatal error over a
  ;; category the operator had already cancelled.
  (let* ((last-negation (position-if (lambda (c)
                                       (member c '("0" "none") :test #'string=))
                                     include :from-end t))
         (effective (if last-negation (nthcdr last-negation include) include)))
    (dolist (cat effective)
      (cond ((member cat '("" "1" "all") :test #'string=)
             (dolist (c +log-categories+) (enable-log-category c)))
            ((member cat '("0" "none") :test #'string=)
             (dolist (c +log-categories+) (disable-log-category c)))
            ((enable-log-category cat))
            ;; Core's wording verbatim (init/common.cpp:91): feature_logging.py
            ;; matches it as a FULL regex, so the old "Unknown logging category
            ;; in -debug: abc" could never match.
            (t (config-error "Unsupported logging category -debug=~A." cat)))))
  (dolist (cat exclude)
    (unless (disable-log-category cat)
      (config-error "Unsupported logging category -debugexclude=~A." cat)))
  (remove-if-not #'log-category-enabled-p +log-categories+))

(defun default-shrink-debug-file-p (include exclude)
  "Core BCLog::Logger::DefaultShrinkDebugFile (logging.cpp:167-170): the
startup scroll is on by default only when NO debug category ends up enabled --
`m_categories == BCLog::NONE' AFTER -debug (INCLUDE) and -debugexclude
(EXCLUDE) have both been applied, which is why -debug=net alone turns it off
and -debug=net -debugexclude=net leaves it on.

Answered on a SCRATCH category set, so asking the question neither installs
the categories early nor reports an unsupported name here: APPLY-LOG-CATEGORIES
does both, later, in Core's own order (Core runs SetLoggingCategories before
StartLogging; we open the log file first, because the deferred config lines
have nowhere to go until it exists). An unsupported name answers NIL -- the
node is about to refuse to start over it, and not scrolling is the direction
that keeps the evidence."
  (let ((*debug-categories* (make-hash-table :test 'equal)))
    (null (handler-case (apply-log-categories include exclude)
            (error () (return-from default-shrink-debug-file-p nil))))))

(defun node-log-category (category format-string &rest args)
  "Emit a :debug entry tagged with CATEGORY iff that category is enabled, or the
global level already includes :debug. Never rate-limited — Core's
detail_LogIfCategoryAndLevelEnabled asserts should_ratelimit is false for every
level it is reached at (util/log.h:104-111)."
  (when (let ((threshold (category-log-level category)))
          (if threshold
              ;; A category with its own threshold is judged only by it — Core
              ;; consults the category level and never falls back to the global
              ;; one for that category (LogAcceptCategory).
              (>= (log-level-value :debug) (log-level-value threshold))
              (or (log-category-enabled-p category)
                  (>= (log-level-value :debug) (log-level-value *current-log-level*)))))
    ;; The category reaches the line now. Core tags a categorized debug line
    ;; with the category alone — `[net] ` — and dropping it here meant every
    ;; log-cat line was indistinguishable from any other debug line, which is
    ;; the whole point of having categories.
    (%log-emit :debug format-string args nil category)))

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


;;;; Operator notify hooks (-blocknotify / -shutdownnotify / -walletnotify)
;;;;
;;;; Run a shell command when something happens. Core runs it through the system
;;;; shell (runCommand, common/run_command.cpp) and so do we: the command comes
;;;; from the operator's own configuration, so the shell is the feature rather
;;;; than a hazard. What must NOT reach the shell unexamined is the SUBSTITUTED
;;;; value, which is why %NOTIFY-SUBSTITUTE validates every one.
;;;;
;;;; Here rather than in src/node/ because the wallet fires -walletnotify from
;;;; AddToWallet, and wallet/wallet-tx.lisp compiles long before src/node/.

(defun %notify-safe-value-p (value)
  "Whether VALUE needs no quoting at all to be substituted into a shell
command: [A-Za-z0-9._-], which is every character with no meaning to the shell.

A hex hash, a decimal height, -1 and \"unconfirmed\" are all in this set, so the
values Core substitutes RAW (%s, %b, %h) take this path. A WALLET NAME is not:
Core's own wallet-name rules admit any character but a path separator, and
feature_notifications.py:43 creates a wallet named after every printable and
control character from 1 to 127 precisely to pin that. %NOTIFY-SHELL-ESCAPE is
the answer for those.

Alphanumeric here is ASCII only -- Core's CHARS_ALPHA_NUM
(util/strencodings.cpp:19-28), the same class SANITIZE-STRING is built on and
for the same reason its docstring gives: CL:ALPHANUMERICP is true of every
Unicode letter and digit, so it would hand a value straight to /bin/sh on a
claim about characters this code has not examined. Escaping is never wrong,
so the set that skips it is the reference's own."
  (and (stringp value)
       (plusp (length value))
       (every (lambda (ch)
                (let ((code (char-code ch)))
                  (or (<= 48 code 57)          ; 0-9
                      (<= 65 code 90)          ; A-Z
                      (<= 97 code 122)         ; a-z
                      (member ch '(#\. #\_ #\-)))))
              value)))

(defun %notify-shell-escape (value)
  "VALUE as one shell word: Core's ShellEscape (common/system.cpp:41-46) --
single-quoted, with each embedded quote written as the four characters
'\"'\"'. Inside single quotes every byte but a quote is literal, so nothing
the value carries can be read as syntax, and the shell removes the quoting
before the command sees the word -- which is what lets a wallet named `a b'
still produce the file `a b_<txid>'."
  (with-output-to-string (out)
    (write-char #\' out)
    (loop for ch across value
          do (if (char= ch #\')
                 (write-string "'\"'\"'" out)
                 (write-char ch out)))
    (write-char #\' out)))

(defun %notify-substitute (command substitutions &key (check t))
  "COMMAND with each (CHAR . VALUE) of SUBSTITUTIONS replacing %CHAR (Core
ReplaceAll). With CHECK (the default), a VALUE that is not already free of
shell syntax is SHELL-ESCAPED first, as Core escapes %w
(wallet/wallet.cpp:1146).

Refusing such a value instead -- which is what this did -- makes the hook fire
nothing at all for a wallet whose name is not [A-Za-z0-9._-], and the node's
own wallet-name rules admit far more than that: feature_notifications.py names
its wallet after every character from 1 to 127 and then waits for one file per
transaction, of which it got none.

A NUL is still refused. It cannot be escaped -- the command reaches
/bin/sh as one argv element, which ends at the first NUL -- so substituting one
would silently truncate the operator's command.

CHECK NIL is for the ONE substitution whose value is quoted by its CALLER --
Core's AlertNotify, which sanitizes a warning message to SAFE_CHARS_DEFAULT and
wraps it in single quotes (kernel_notifications.cpp:36-42). ALERT-NOTIFY is its
only user; nothing else may pass NIL.

Single pass, so a substituted value can never itself be rescanned for a
placeholder: a block hash cannot smuggle in a %w."
  (when check
    (setf substitutions
          (loop for (char . value) in substitutions
                do (unless (and (stringp value) (not (find #\Nul value)))
                     (internal-error "Refusing to substitute ~S into a notify command"
                                     value))
                collect (cons char (if (%notify-safe-value-p value)
                                       value
                                       (%notify-shell-escape value))))))
  (let ((out (make-string-output-stream))
        (i 0)
        (n (length command)))
    (loop while (< i n)
          do (let ((hit (and (< (1+ i) n)
                             (char= (char command i) #\%)
                             (assoc (char command (1+ i)) substitutions
                                    :test #'char=))))
               (if hit
                   (progn (write-string (cdr hit) out) (incf i 2))
                   (progn (write-char (char command i) out) (incf i)))))
    (get-output-stream-string out)))

;;; --- Deferred startup logging ---

(defvar *deferred-log-lines* nil
  "Log lines produced BEFORE the log file exists, held until it does.

Config parsing runs before START-FILE-LOGGING: the datadir, the network and the
log path itself are all decisions made from the very options being logged. A
LOG-INFO issued there reaches the console and nothing else, so every
`Command-line arg:`/`Config file arg:`/`Setting file arg:` line — the exact
lines Core's functional tests read back out of debug.log to check how an option
resolved — was invisible in the file. Kept newest-last; FLUSH-DEFERRED-LOG-LINES
empties it.")

(defun defer-log (level format-string &rest args)
  "Queue one log line for FLUSH-DEFERRED-LOG-LINES. LEVEL is :info or :warn."
  (push (list level (apply #'format nil format-string args)) *deferred-log-lines*)
  nil)

(defun flush-deferred-log-lines ()
  "Emit everything DEFER-LOG queued, in the order it was queued, and forget it.

Identical lines are emitted ONCE. The config text is parsed several times on the
way up — once to resolve the network, once for the merged settings, once for the
unknown-key scan, once more to render the arg log — and a warning raised inside
the parser would otherwise appear once per pass. Startup config lines are
statements about the configuration, so a repeat is always an artifact of how
many times we looked at it."
  (let ((lines (remove-duplicates (nreverse *deferred-log-lines*)
                                  :test #'equal :from-end t)))
    (setf *deferred-log-lines* nil)
    (dolist (line lines)
      (ecase (first line)
        (:info (log-info "~A" (second line)))
        (:warn (log-warn "~A" (second line)))))))

(defun report-init-error (control &rest args)
  "Print one startup refusal the way Core's noui prints an InitError: the
message under an `Error: ' caption, on stderr (noui.cpp:29-31). Logs it too,
because Core's InitError goes to the log as well.

Unlike signalling an INIT-ERROR this does NOT end the process, which is the
whole reason it exists: Core reports some refusals in two lines, the specific
complaint and then the fatal error that actually stops the node -- an index
whose best block is past the pruned data is reported at init.cpp:2366-2381
and stopped at :2040-2043 -- and a functional test compares the WHOLE of
stderr against both."
  (let ((message (apply #'format nil control args)))
    (log-error "~A" message)
    (ignore-errors
      (format *error-output* "Error: ~A~%" message)
      (finish-output *error-output*))
    message))

(defun run-notify-command (command &key value substitutions (wait nil) (check t))
  "Run COMMAND through the shell. VALUE is shorthand for a single %s
substitution; SUBSTITUTIONS is the general (CHAR . VALUE) form.

WAIT NIL detaches, as Core does for -blocknotify and -walletnotify (\"thread
runs free\", init.cpp:2017, wallet.cpp:1149) — a hook must never be able to
stall block connection. WAIT T is for -shutdownnotify, which Core joins.
CHECK NIL waives the shell-safe check on the substituted values; see
%NOTIFY-SUBSTITUTE, and only ALERT-NOTIFY may use it.

Never signals: a failing hook is the operator's problem to see in the log, not
a reason to fail whatever triggered it."
  (handler-case
      (let* ((subs (append (when value (list (cons #\s value))) substitutions))
             (full (if subs (%notify-substitute command subs :check check) command)))
        (if wait
            (uiop:run-program (list "/bin/sh" "-c" full)
                              :ignore-error-status t
                              :output nil :error-output nil)
            (uiop:launch-program (list "/bin/sh" "-c" full)
                                 :output nil :error-output nil))
        t)
    (error (e)
      (log-warn "notify command failed: ~A" e)
      nil)))

;;; --- The node's warnings, and -alertnotify (Core node/warnings.cpp) ---------
;;;
;;; Core keeps ONE map of active warnings and answers two channels from it: the
;;; `warnings' array of getblockchaininfo / getnetworkinfo / getmininginfo
;;; (GetWarningsForRpc, warnings.cpp:71-83), and the -alertnotify command, fired
;;; from KernelNotifications::warningSet for the KERNEL warnings only
;;; (kernel_notifications.cpp:79-85). Here rather than in src/node/ because the
;;; other operator hooks are here and everything above this layer can reach it;
;;; validation is one of the producers and knows nothing about the node.

(defvar *client-version-is-release* t
  "Core CLIENT_VERSION_IS_RELEASE (clientversion.cpp:42). When NIL the warnings
map starts with Core's pre-release entry (warnings.cpp:20-27).

Left T here on purpose: the `warnings' array is a monitoring channel, and a
message that is present on every node at every moment is the one thing that
teaches an operator to stop reading it -- which is the failure this whole
registry exists to fix. A packager who ships a test build flips it.")

(defparameter +warning-ids+
  '(:unknown-new-rules-activated :large-work-invalid-chain
    :clock-out-of-sync :pre-release-test-build :fatal-internal-error)
  "Every warning id, in the order Core's std::map<warning_type, ...> yields
them: the kernel::Warning variants first (kernel/warning.h:9-12), then the
node::Warning ones (node/warnings.h:23-27). GetMessages is documented as
`sorted by the warning_type id', so the RPC array's order is this list's.")

(defvar *warnings* '()
  "The active warnings as an alist (id . message) -- Core node::Warnings'
m_warnings. Read through WARNING-MESSAGES, which imposes +WARNING-IDS+'s order.")

(defvar *warnings-lock* (bt:make-lock "warnings")
  "Core Warnings::m_mutex: the producers are validation threads and the readers
are RPC threads.")

(defun set-warning (id message)
  "Record the warning ID with MESSAGE. Returns T only when the state CHANGED,
i.e. when no warning with this id was already active -- Core Warnings::Set
returns `inserted' and ignores the new message otherwise (warnings.cpp:28-33).

That return value is what makes -alertnotify fire once per transition instead
of once per block, so a caller that ignores it has broken the option."
  (bt:with-lock-held (*warnings-lock*)
    (unless (assoc id *warnings*)
      (push (cons id message) *warnings*)
      t)))

(defun unset-warning (id)
  "Clear the warning ID. Returns T only when one was active (Core
Warnings::Unset, warnings.cpp:35-40)."
  (bt:with-lock-held (*warnings-lock*)
    (when (assoc id *warnings*)
      (setf *warnings* (remove id *warnings* :key #'car))
      t)))

(defun warning-messages ()
  "Every active warning's message, in Core's map order (Core
Warnings::GetMessages, warnings.cpp:42-51)."
  (let ((active (bt:with-lock-held (*warnings-lock*) (copy-alist *warnings*))))
    (loop for id in +warning-ids+
          for cell = (assoc id active)
          when cell collect (cdr cell))))

(defun warnings-for-rpc ()
  "The `warnings' field of getblockchaininfo / getnetworkinfo / getmininginfo
(Core GetWarningsForRpc, warnings.cpp:71-83) -- an ARRAY of messages, empty
when the node has nothing to report."
  (or (warning-messages) #()))

(defun reset-warnings ()
  "Start this run's warnings map -- Core's Warnings CONSTRUCTOR
(warnings.cpp:20-27), which is empty but for the pre-release build entry.

Called once per run so an in-image restart does not inherit the previous node's
warnings; the whole point of the map is that a warning describes the node that
is running now."
  (bt:with-lock-held (*warnings-lock*) (setf *warnings* '()))
  (unless *client-version-is-release*
    (set-warning :pre-release-test-build
                 "This is a pre-release test build - use at your own risk - do not use for mining or merchant applications"))
  t)

;;; --- AbortNode (Core node/abort.cpp) ---------------------------------------

(defvar *fatal-error-shutdown-function* nil
  "Called with the message by FATAL-ERROR to stop the node -- the
shutdown_request half of Core's AbortNode (node/abort.cpp:23-25). NODE-MAIN
installs a request for a non-clean shutdown; everywhere else (tests, a REPL)
it stays NIL and a fatal error is reported without stopping the image, which
is Core's own m_shutdown_on_fatal_error = false (kernel_notifications.h).")

(defun fatal-error (message)
  "Core FatalError -> KernelNotifications::fatalError -> AbortNode
(validation.cpp:2133-2137, node/kernel_notifications.cpp:97-101,
node/abort.cpp:18-26): record the FATAL_INTERNAL_ERROR warning, report
MESSAGE the way InitError does -- logged, and on stderr under Core's caption
`A fatal internal error occurred, see debug.log for details: ' -- and ask
the node to stop with a failing exit status.

Reported once: Core stops the node after the first, and a caller that meets
the same fault again before the shutdown lands (the sync loop retrying the
same reorg) must not add a second line to stderr, which
feature_abortnode.py:39 compares whole. Returns MESSAGE."
  (when (set-warning :fatal-internal-error message)
    (report-init-error
     "A fatal internal error occurred, see debug.log for details: ~A" message)
    (let ((shutdown *fatal-error-shutdown-function*))
      (when shutdown (funcall shutdown message))))
  message)

(defvar *alert-notify-command* nil
  "Core -alertnotify: a shell command run when a KERNEL warning appears, with
%s replaced by the message. NIL (Core's empty default) means no command.")

(defun alert-notify (message)
  "Core AlertNotify (node/kernel_notifications.cpp:30-47): run
-alertnotify with %s replaced by MESSAGE, detached.

MESSAGE is sanitized to Core's SAFE_CHARS_DEFAULT and then wrapped in single
quotes, exactly as Core does -- and that order is what makes the quoting safe,
since the safe set contains no quote of its own."
  (let ((command *alert-notify-command*))
    (when (and (stringp command) (plusp (length command)))
      (run-notify-command command
                          :value (format nil "'~A'"
                                         (bl.bytes:sanitize-string message))
                          :check nil))))

(defun trace-thread (name function)
  "Core util::TraceThread (util/thread.cpp:16-30): run FUNCTION as the body of a
named thread, bracketed by `<NAME> thread start' and `<NAME> thread exit'.

The pair is what Core's functional tests wait on to interrupt a node at a
precise point of start-up (feature_init.py:63-85) and to see that a role's
service has actually begun (feature_config_args.py:305 waits for `opencon
thread start', so that ThreadOpenConnections' start time is set). Core writes
the exit line only on a normal return: an escaping condition is reported the
way PrintExceptionContinue reports it and then re-signalled, and no `thread
exit' is written.

NAME is Core's name for the ROLE the thread performs, so an operator comparing
the two logs reads the same word. This node runs fewer threads than Core does;
only the threads that exist are traced, and a Core thread name with no thread
of its own here stays absent rather than being invented."
  (log-info "~A thread start" name)
  (handler-bind ((error (lambda (c)
                          ;; PrintExceptionContinue: report it, then let it
                          ;; propagate (util/thread.cpp:23-28).
                          (log-error "~A thread: ~A" name c))))
    (funcall function))
  (log-info "~A thread exit" name))

(defun set-kernel-warning (id message)
  "Core KernelNotifications::warningSet (kernel_notifications.cpp:79-85): record
the warning and, ONLY when the state changed, fire -alertnotify. Returns what
SET-WARNING returned.

Kernel warnings are the two an operator is paged about --
:LARGE-WORK-INVALID-CHAIN and :UNKNOWN-NEW-RULES-ACTIVATED (kernel/warning.h).
The node:: ones reach the RPC array through SET-WARNING and never the pager, as
in Core."
  (when (set-warning id message)
    (alert-notify message)
    t))
