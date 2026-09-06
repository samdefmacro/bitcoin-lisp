(in-package #:bitcoin-lisp.tests)

(def-suite :logging-tests
  :description "Log formatting, control-character escaping and rate limiting"
  :in :bitcoin-lisp-tests)

(in-suite :logging-tests)

;;; --- formatting -------------------------------------------------------------

(test log-entry-is-one-line-even-for-a-condition
  "A condition report must not be pretty-printed across the log.

With *PRINT-PRETTY* left on, `~A' of a multi-line object is laid out from the
current column, so a type error appended to a log line becomes ten indented
lines whose first carries only the word `The'. That is how the fd>1023 select()
failure reported itself on mainnet; the guard is the binding in
FORMAT-LOG-ENTRY, so assert against the shape that reproduces it."
  (let ((condition (make-condition 'type-error
                                   :datum 3119
                                   :expected-type '(unsigned-byte 10)))
        (*print-right-margin* 40))
    ;; The symptom, so the test fails if the reproducer stops reproducing.
    (is (find #\Newline (let ((*print-pretty* t))
                          (format nil "prefix: ~A" condition))))
    (let ((entry (bl.log::format-log-entry :warn "boom: ~A" (list condition))))
      (is (null (find #\Newline entry)))
      (is (search "3119" entry))
      (is (search "UNSIGNED-BYTE 10" entry)))))

(test log-escapes-control-characters-but-keeps-newline
  "Core BCLog::LogEscapeMessage (logging.cpp:329-340)."
  (is (string= "plain ascii" (bl.log::%log-escape-message "plain ascii")))
  ;; Identity, not just equality: an unescaped string is returned as-is.
  (let ((s "nothing to escape"))
    (is (eq s (bl.log::%log-escape-message s))))
  (is (string= (format nil "a~%b") (bl.log::%log-escape-message (format nil "a~%b"))))
  (is (string= "cr\\x0d esc\\x1b del\\x7f nul\\x00"
               (bl.log::%log-escape-message
                (format nil "cr~C esc~C del~C nul~C"
                        #\Return (code-char 27) (code-char 127) (code-char 0)))))
  ;; A peer-supplied subversion string reaches the log, so the carriage return
  ;; that would let it overwrite the line is escaped. A newline is NOT — Core
  ;; passes it through so a genuinely multi-line message stays readable — which
  ;; is why this is escaping and not sanitising.
  (is (string= "peer /Satoshi:1.0/\\x0d[2026-01-01 00:00:00] ERROR: fake"
               (bl.log::%log-escape-message
                (format nil "peer /Satoshi:1.0/~C[2026-01-01 00:00:00] ERROR: fake"
                        #\Return)))))

;;; --- rate limiting (Core BCLog::LogRateLimiter) ------------------------------

(defmacro with-fresh-rate-limiter ((&key (limit t)) &body body)
  `(let ((bl.log:*log-rate-locations* (make-hash-table :test 'equal))
         (bl.log:*log-rate-window-start* (get-universal-time))
         (bl.log:*log-suppressions-active* nil)
         (bl.log:*log-rate-limit* ,limit)
         (bl.log:*log-stream* nil)
         (bl.log:*log-file-stream* nil))
     ,@body))

(test log-rate-limiter-state-machine
  "Consume returns Core's three statuses, and the budget is per location."
  (with-fresh-rate-limiter ()
    (is (eq :unsuppressed (bl.log::%log-rate-consume "site A" 10)))
    (is (eq :newly-suppressed
            (bl.log::%log-rate-consume
             "site A" (* 2 bl.log::+log-ratelimit-max-bytes+))))
    (is (eq :still-suppressed (bl.log::%log-rate-consume "site A" 10)))
    ;; A different location keeps its own budget — suppressing one site must
    ;; never silence the rest of the node.
    (is (eq :unsuppressed (bl.log::%log-rate-consume "site B" 10)))
    (is-true bl.log:*log-suppressions-active*)))

(test log-rate-limiter-exhausts-a-budget-gradually
  "The budget is bytes, not calls: many small writes eventually suppress."
  (with-fresh-rate-limiter ()
    (let* ((chunk 1024)
           (calls (ceiling bl.log::+log-ratelimit-max-bytes+ chunk))
           (statuses (loop repeat (1+ calls)
                           collect (bl.log::%log-rate-consume "site" chunk))))
      (is (every (lambda (s) (eq s :unsuppressed)) (subseq statuses 0 calls)))
      (is (eq :newly-suppressed (car (last statuses)))))))

(test log-rate-limiter-window-reset-restores-and-reports
  "Reset clears the budget and reports what was dropped (Core Reset)."
  (with-fresh-rate-limiter ()
    (bl.log::%log-rate-consume
     "noisy site" (* 2 bl.log::+log-ratelimit-max-bytes+))
    (is-true bl.log:*log-suppressions-active*)
    ;; Backdate the window so the lazy close fires.
    (setf bl.log:*log-rate-window-start*
          (- (get-universal-time) bl.log::+log-ratelimit-window-seconds+ 1))
    (bl.log::%log-maybe-reset-window)
    (is-false bl.log:*log-suppressions-active*)
    (is (zerop (hash-table-count bl.log:*log-rate-locations*)))
    (let ((restart (find-if (lambda (e) (and e (search "Restarting logging" e)))
                            bl.log:*log-buffer*)))
      (is-true restart)
      (is (search "noisy site" restart)))))

(test log-rate-limiter-suppresses-the-file-not-the-console
  "Core: \"Suppressing logging to disk ... Console logging unaffected.\""
  (with-fresh-rate-limiter ()
    (let ((console (make-string-output-stream))
          (file (make-string-output-stream)))
      (let ((bl.log:*log-stream* console)
            (bl.log:*log-file-stream* file))
        (bl.log::%log-emit :info "big ~A" (list (make-string 4096 :initial-element #\x)))
        ;; Blow the budget from the same location, then write again.
        (bl.log::%log-rate-consume
         "big ~A" (* 2 bl.log::+log-ratelimit-max-bytes+))
        (bl.log::%log-emit :info "big ~A" (list "second")))
      (let ((console-text (get-output-stream-string console))
            (file-text (get-output-stream-string file)))
        (is (search "second" console-text))
        (is (null (search "second" file-text)))
        ;; Every line carries Core's suppression marker while one is active.
        (is (search "[*] " console-text))))))

(test log-rate-limiter-never-suppresses-its-own-notices
  "The NEWLY_SUPPRESSED notice is emitted with should_ratelimit=false, so it
cannot be eaten by the limiter that produced it."
  (with-fresh-rate-limiter ()
    (let ((file (make-string-output-stream)))
      (let ((bl.log:*log-file-stream* file))
        (bl.log::%log-emit
         :info "wordy ~A" (list (make-string (* 2 bl.log::+log-ratelimit-max-bytes+)
                                             :initial-element #\y))))
      (let ((text (get-output-stream-string file)))
        (is (search "Excessive logging detected" text))
        ;; Core writes the entry that tripped the limit: "Last log entry."
        (is (search "Last log entry." text))
        (is (search "yyyy" text))))))

(test debug-and-category-logging-are-not-rate-limited
  "Core rate-limits Info and louder only (util/log.h:91-113): -debug users are
assumed to accept the volume."
  (with-fresh-rate-limiter ()
    (let ((bl.log:*current-log-level* :debug))
      (bl.log:node-log :debug "quiet ~A" "x")
      (bl.log::node-log-category "validation" "cat ~A" "x"))
    (is (zerop (hash-table-count bl.log:*log-rate-locations*)))
    (bl.log:node-log :warn "loud ~A" "x")
    (is (= 1 (hash-table-count bl.log:*log-rate-locations*)))))

(test log-rate-limit-can-be-turned-off
  "-logratelimit=0 (Core -logratelimit)."
  (with-fresh-rate-limiter (:limit nil)
    (let ((file (make-string-output-stream)))
      (let ((bl.log:*log-file-stream* file))
        (dotimes (i 3)
          (bl.log::%log-emit
           :info "huge ~A" (list (make-string bl.log::+log-ratelimit-max-bytes+
                                              :initial-element #\z)))))
      (is (null (search "Excessive logging detected" (get-output-stream-string file)))))
    (is (zerop (hash-table-count bl.log:*log-rate-locations*)))))

;;;; --- Core's [category:level] prefix (BCLog::LogPrefix) ---

(test log-prefix-matches-core-for-every-shape
  "Core's LogPrefix (logging.cpp:343-367) decides the tag on every log line,
and the functional tests match on the rendered result — feature_config_args.py
looks for the literal '[warning] Parsed potentially confusing double-negative'.

The uncategorized-INFO case is the one that changes most lines: Core prints NO
tag there, where this used to print `INFO: `."
  (flet ((p (cat level) (bl.log::log-category-level-prefix cat level)))
    (is (string= "" (p nil :info))
        "an uncategorized info line carries no tag in Core")
    (is (string= "[warning] " (p nil :warn)))
    (is (string= "[error] " (p nil :error)))
    (is (string= "[debug] " (p nil :debug)))
    ;; A category implies debug, so Core prints the category alone.
    (is (string= "[net] " (p "net" :debug)))
    (is (string= "[net:warning] " (p "net" :warn)))
    (is (string= "[net:error] " (p "net" :error)))
    ;; "all" is Core's LogFlags::ALL, which is the no-category case.
    (is (string= "" (p "all" :info)))
    (is (string= "[warning] " (p "all" :warn)))))

(test log-level-names-are-cores-spelling
  ":WARN prints as \"warning\". Core's LogLevelToStr has no \"warn\", and a
test matching Core's word would never fire on ours."
  (is (string= "warning" (bl.log::log-level-name :warn)))
  (is (string= "error" (bl.log::log-level-name :error)))
  (is (string= "info" (bl.log::log-level-name :info)))
  (is (string= "debug" (bl.log::log-level-name :debug)))
  (is (string= "trace" (bl.log::log-level-name :trace))))

(test log-entry-renders-the-prefix
  "The whole line, not just the prefix helper: a warning must contain Core's
tag immediately before the message, and an info line must have no tag between
the timestamp and the message."
  (let ((warn (bl.log::format-log-entry :warn "hello ~A" '("world")))
        (info (bl.log::format-log-entry :info "hello ~A" '("world")))
        (net (bl.log::format-log-entry :debug "hello ~A" '("world") "net")))
    (is-true (search "[warning] hello world" warn))
    (is-true (search "] hello world" info))
    (is-false (search "[warning]" info))
    (is-false (search "INFO:" info))
    (is-true (search "[net] hello world" net))))

(test log-cat-tags-the-line-with-its-category
  "log-cat's category used to be consulted for the enabled/disabled decision
and then DROPPED, so every categorized line came out as an untagged debug line
— there was no way to tell from the log which subsystem wrote it."
  (let ((bl.log:*current-log-level* :debug)
        (bl.log:*log-file-stream* nil))
    (bl:log-cat "net" "a categorized line")
    (let ((entry (find-if (lambda (e) (and e (search "a categorized line" e)))
                          bl.log:*log-buffer*)))
      (is-true entry "the line reached the buffer")
      (when entry
        (is-true (search "[net] a categorized line" entry))))))

(test unsupported-logging-category-uses-cores-wording
  "feature_logging.py matches this as a FULL regex, so the wording is the
contract: 'Error: Unsupported logging category -debug=abc.' — trailing period
included. Ours said 'Unknown logging category in -debug: abc', which could
never match however correct the behaviour was."
  (let ((e (handler-case (bl.log:apply-log-categories '("abc") nil)
             (error (c) (princ-to-string c)))))
    (is (string= "Unsupported logging category -debug=abc." e)))
  (let ((e (handler-case (bl.log:apply-log-categories nil '("xyz"))
             (error (c) (princ-to-string c)))))
    (is (string= "Unsupported logging category -debugexclude=xyz." e)))
  ;; A known category still applies without complaint.
  (is-true (bl.log:apply-log-categories '("net") nil)))

;;;; --- -loglevel=<category>:<level> (Core SetLoggingLevel) ---

(test loglevel-spec-tells-a-category-from-a-global-level
  "Core splits on the first ':' at index 3 or later (init/common.cpp:63) — a
level name is never long enough to contain one there, so that is how
`-loglevel=net:debug` is told from a bare `-loglevel=trace`."
  (is (equal '(nil :debug) (multiple-value-list
                            (bl:parse-loglevel-spec "trace"))))
  (is (equal '(nil :info) (multiple-value-list
                           (bl:parse-loglevel-spec "info"))))
  (is (equal '("net" :debug) (multiple-value-list
                              (bl:parse-loglevel-spec "net:debug")))))

(test loglevel-spec-rejects-an-unknown-half-with-cores-wording
  "Both halves must be known and the message is matched by feature_logging.py.
An option that silently does nothing is how an operator ends up staring at a
log that will never contain what they asked for."
  (dolist (bad '("nosuch:debug" "net:abc"))
    (let ((e (handler-case (progn (bl:parse-loglevel-spec bad) nil)
               (error (c) (princ-to-string c)))))
      (is-true e "~A must be refused" bad)
      (when e
        (is-true (search (format nil "Unsupported category-specific logging level -loglevel=~A." bad) e))
        (is-true (search "Expected -loglevel=<category>:<loglevel>." e))
        (is-true (search "Valid loglevels: info, debug, trace." e))))))

(test a-category-threshold-overrides-the-global-level
  "Core judges a categorized line by that category's own threshold and does not
fall back to the global one for it (LogAcceptCategory). Setting
-loglevel=net:debug therefore surfaces net lines on a node whose global level
is info, without -debug=net."
  (let ((bl.log:*category-log-levels* (make-hash-table :test 'equal :synchronized t))
        (bl.log::*debug-categories* (make-hash-table :test 'equal))
        (bl.log:*current-log-level* :info)
        (bl.log:*log-file-stream* nil))
    ;; Without a threshold and without -debug=net, a net line is suppressed.
    (bl:log-cat "net" "suppressed line one")
    (is-false (find-if (lambda (e) (and e (search "suppressed line one" e)))
                       bl.log:*log-buffer*))
    ;; With one, it is emitted — and carries the category tag.
    (is-true (bl:set-category-log-level "net" :debug))
    (bl:log-cat "net" "visible line two")
    (let ((entry (find-if (lambda (e) (and e (search "visible line two" e)))
                          bl.log:*log-buffer*)))
      (is-true entry)
      (when entry (is-true (search "[net] visible line two" entry))))
    ;; An unknown category cannot be given one.
    (is-false (bl:set-category-log-level "nosuch" :debug))))

(test debug-categories-before-the-last-negation-are-disregarded
  "Core finds the LAST -debug=0/none and processes only the categories after it
(init/common.cpp:82-88), so everything before it is disregarded — invalid names
included. feature_logging.py drives exactly
`-debug=http -debug=abc -debug=none -debug=rpc -debug=net` and requires the
node to start, with http off and the invalid `abc` never mentioned.

Validating the whole list made that a fatal error over a category the operator
had already cancelled."
  (let ((bl.log::*debug-categories* (make-hash-table :test 'equal)))
    (bl.log:apply-log-categories '("http" "abc" "none" "rpc" "net") nil)
    (is-false (bl:log-category-enabled-p "http")
              "a category named before the negation must not survive it")
    (is-true (bl:log-category-enabled-p "rpc"))
    (is-true (bl:log-category-enabled-p "net")))
  ;; An invalid name AFTER the last negation is still fatal.
  (let ((bl.log::*debug-categories* (make-hash-table :test 'equal)))
    (signals error (bl.log:apply-log-categories '("none" "abc") nil)))
  ;; And with no negation at all, the whole list is validated as before.
  (let ((bl.log::*debug-categories* (make-hash-table :test 'equal)))
    (signals error (bl.log:apply-log-categories '("net" "abc") nil))))

;;; --- -shrinkdebugfile (GA11 e9d39df8) ---------------------------------------

(test shrinkdebugfile-is-a-real-option-with-cores-derived-default
  "-shrinkdebugfile left the accept-and-drop list (GA11 e9d39df8). Its default
is DERIVED from another option, which is why the start-node keyword has to tell
`not given' from `=0': Core's DefaultShrinkDebugFile() is
`m_categories == BCLog::NONE' (logging.cpp:167-170), read at
init/common.cpp:108-113, so a node started with any -debug category does not
scroll its log and -shrinkdebugfile=0 keeps it whole in every case."
  (is (eq :start-node (bl.cfg:config-option-kind
                       (bl.cfg:find-config-option "shrinkdebugfile"))))
  (is-false (bl.cfg:core-only-option-p "shrinkdebugfile"))
  ;; Given, it reaches the keyword; absent, the keyword is not there at all, so
  ;; START-NODE's :UNSET default survives and the derivation below runs.
  (let ((plist (start-node-plist '("-regtest" "-shrinkdebugfile=0"))))
    (is-true (member :shrink-debug-file plist))
    (is-false (getf plist :shrink-debug-file)))
  (let ((plist (start-node-plist '("-regtest" "-shrinkdebugfile=1"))))
    (is-true (getf plist :shrink-debug-file)))
  (is-false (member :shrink-debug-file (start-node-plist '("-regtest"))))
  ;; Core's derivation, answered over the RAW -debug / -debugexclude lists,
  ;; because ours are applied only after the log file exists.
  (is-true (bl.log:default-shrink-debug-file-p nil nil))
  (is-false (bl.log:default-shrink-debug-file-p '("net") nil))
  (is-true (bl.log:default-shrink-debug-file-p '("net") '("net"))
           "a category excluded again leaves m_categories NONE, so Core scrolls")
  (is-true (bl.log:default-shrink-debug-file-p '("none") nil))
  ;; Asking must not INSTALL the categories: the real set comes back unchanged,
  ;; and the unsupported name is reported later, by APPLY-LOG-CATEGORIES.
  (let ((before (bl:log-category-enabled-p "net")))
    (is-false (bl.log:default-shrink-debug-file-p '("nosuchcategory") nil))
    (bl.log:default-shrink-debug-file-p '("net") nil)
    (is (eq before (bl:log-category-enabled-p "net"))
        "asking the question must not enable a category")))

(test start-file-logging-scrolls-only-when-asked
  "The gate itself. START-FILE-LOGGING scrolled the log unconditionally, so an
operator reproducing a fault under -debug lost everything past the last 10 MB
of the evidence on the restart that reproduces it — and -shrinkdebugfile=0 did
not stop it either. The default (:SHRINK T) case is the positive control: a
gate that never scrolls at all cannot pass this test."
  (let* ((dir (ensure-directories-exist
               (merge-pathnames "test-shrink-gate/" (uiop:temporary-directory))))
         (path (merge-pathnames "debug.log" dir))
         (saved-stream bl.log:*log-file-stream*)
         (saved-path bl:*log-file-path*)
         (big 12000000))
    (setf bl.log:*log-file-stream* nil)
    (unwind-protect
         (flet ((write-log ()
                  (with-open-file (s path :direction :output :if-exists :supersede
                                          :if-does-not-exist :create
                                          :element-type '(unsigned-byte 8))
                    (write-sequence (make-array big :element-type '(unsigned-byte 8)
                                                    :initial-element 65)
                                    s)))
                (open-size ()
                  ;; Close first: the file is open for append at this point.
                  (close bl.log:*log-file-stream*)
                  (setf bl.log:*log-file-stream* nil)
                  (with-open-file (s path :direction :input
                                          :element-type '(unsigned-byte 8))
                    (file-length s))))
           (write-log)
           (bl:start-file-logging path)
           (is (< (open-size) big) "the unasked default must still scroll")
           (write-log)
           (bl:start-file-logging path :shrink nil)
           (is (= big (open-size))
               "-shrinkdebugfile=0 (or any -debug category) keeps the log whole"))
      (progn
        (when bl.log:*log-file-stream*
          (ignore-errors (close bl.log:*log-file-stream*)))
        (setf bl.log:*log-file-stream* saved-stream
              bl:*log-file-path* saved-path)
        (ignore-errors (delete-file path))))))
